#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>
#include "alsa_pcm_api.h"
#include "audio_out.h"
#define WORD2INT(x) ((x) < -32766.5f ? -32767 : ((x) > 32766.5f ? 32767 : lrintf(x)))
void *mempool_alloc_small(size_t sizeofobject, unsigned int pool_id);
void mempool_free_small(unsigned int pool_id, int pool_unref_count);

typedef struct _alsa_mmap_t {
    struct snd_pcm_mmap_status *mmap_status;
    void *mmap_ptr;
    uint64_t appl_ptr;
    uint32_t frame_size, last_len;
    int ver;
	int snd_fd;
    TimeFilter tf;
    struct timespec tv;
} alsa_mmap_t;

int snd_pcm_start(int snd_fd)
{
	return ioctl(snd_fd, SNDRV_PCM_IOCTL_START);
}

int snd_pcm_prepare(int snd_fd)
{
	return ioctl(snd_fd, SNDRV_PCM_IOCTL_PREPARE);
}

int snd_pcm_status(int snd_fd, snd_pcm_status_t *status)
{
	return ioctl(snd_fd, SNDRV_PCM_IOCTL_STATUS, status);
}

static size_t page_align(size_t size)
{
    //size_t r, psz = getpagesize();
    size_t r, psz = 4096;
    r = size & (psz - 1);
    if (r)
        size += (psz - r);
    return size;
}

static void snd_pcm_sw_params_default(snd_pcm_sw_params_t *params, uint32_t period_size)
{
    params->tstamp_mode = SND_PCM_TSTAMP_ENABLE;
    params->period_step = 1;
    params->sleep_min = 0;
    params->avail_min = period_size;
    params->xfer_align = period_size;
    params->start_threshold = 1;
    params->silence_threshold = 0;
    params->silence_size = 0;
    params->boundary = (1ULL << 30);
    params->stop_threshold = params->boundary;
    params->proto = 0x20013;
}

void alsa_mmap_close(void *_ao)
{
    alsa_mmap_t *ao = (alsa_mmap_t*)_ao;
	munmap(ao->mmap_ptr, 65536);
    munmap(ao->mmap_status, page_align(sizeof(struct snd_pcm_mmap_status)));
    ioctl(ao->snd_fd, SNDRV_PCM_IOCTL_HW_FREE);
    close(ao->snd_fd);
}

void *alsa_mmap_open(const char *devpath, uint32_t *samplerate, uint32_t frame_size, uint8_t channels, uint32_t *_ver)
{
    size_t sz = 0;
    struct snd_pcm_sync_ptr sync_ptr;
    snd_pcm_sw_params_t swparams;
    alsa_mmap_t *ao = mempool_alloc_small(sizeof(alsa_mmap_t), 2);
    ao->snd_fd = -1;

    if (!devpath) {
        devpath = "/dev/snd/pcmC1D0p";
    }

    ao->snd_fd = open(devpath, O_RDWR);
    if (ao->snd_fd < 0)
        return NULL;

    if (ioctl(ao->snd_fd, SNDRV_PCM_IOCTL_PVERSION, &ao->ver) < 0) {
        if (ao->snd_fd >= 0)
            close(ao->snd_fd);
        return NULL;
    }
    if(_ver) *_ver = ao->ver;

    frame_size >>= (2-channels);
	alsa_init_hwparams(ao->snd_fd, SND_PCM_ACCESS_MMAP_INTERLEAVED, samplerate, frame_size, channels);
    timefilter_new(&ao->tf, 1.0 / *samplerate, 1024, 3.0);
    snd_pcm_sw_params_default(&swparams, frame_size);
    ioctl(ao->snd_fd, SNDRV_PCM_IOCTL_SW_PARAMS, &swparams);
    ao->mmap_status = mmap(NULL, page_align(sizeof(struct snd_pcm_mmap_status)),
                           PROT_READ, MAP_FILE|MAP_SHARED, ao->snd_fd, SNDRV_PCM_MMAP_OFFSET_STATUS);
    sz = 65536;
    ao->mmap_ptr = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, ao->snd_fd, 0);
    ao->appl_ptr = ao->mmap_status->hw_ptr;
    ao->last_len = 0;
    ao->frame_size = frame_size;
    ao->tv.tv_sec = 0;
    //ao->tv.tv_nsec = (((frame_size * 1000000) / *samplerate) << 10);
    ao->tv.tv_nsec = (((frame_size * 1000000) / *samplerate) << 9);
	sync_ptr.flags = 0;
    sync_ptr.c.control.avail_min = frame_size;
    sync_ptr.c.control.appl_ptr = 1;
	ioctl(ao->snd_fd, SNDRV_PCM_IOCTL_SYNC_PTR, &sync_ptr);
    ioctl(ao->snd_fd, SNDRV_PCM_IOCTL_START);
    return ao;
}

void alsa_mmap_write_flt(void *_ao, float *buf, uint32_t bufsize)
{
  alsa_mmap_t *ao = (alsa_mmap_t*)_ao;
  int16_t *optr = ao->mmap_ptr;
  size_t i, diff;

  nanosleep(&(ao->tv), NULL);
  diff = (ao->mmap_status->hw_ptr & 0xFFFF) - ao->last_len;
  while(diff < 1) {
    nanosleep(&(ao->tv), NULL);
    diff = (ao->mmap_status->hw_ptr & 0xFFFF) - ao->last_len;
  }
  ao->last_len = (ao->mmap_status->hw_ptr & 0xFFFF);
  timefilter_update(&ao->tf, ao->mmap_status->tstamp.tv_sec, 1024);

  for (i=0; i<bufsize; i++) {
    optr[((ao->appl_ptr + i) & ((ao->frame_size-1)>>1))] = WORD2INT(buf[i]*32768.0f);
  }
  ao->appl_ptr += bufsize;
}

void alsa_mmap_write_s16(void *_ao, int16_t *buf, uint32_t bufsize)
{
  alsa_mmap_t *ao = (alsa_mmap_t*)_ao;
  int16_t *optr = ao->mmap_ptr;
  size_t i, diff;

  nanosleep(&(ao->tv), NULL);
  diff = (ao->mmap_status->hw_ptr & 0xFFFF) - ao->last_len;
  while(diff < 1) {
    nanosleep(&(ao->tv), NULL);
    diff = (ao->mmap_status->hw_ptr & 0xFFFF) - ao->last_len;
  }
  ao->last_len = (ao->mmap_status->hw_ptr & 0xFFFF);
  timefilter_update(&ao->tf, ao->mmap_status->tstamp.tv_sec, 1024);

  for (i=0; i<bufsize; i++) {
    optr[((ao->appl_ptr + i) & ((ao->frame_size-1)>>1))] = buf[i];
  }
  ao->appl_ptr += bufsize;
}

