#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/soundcard.h>
#include <math.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include "audio_out.h"
#ifndef SNDCTL_DSP_COOKEDMODE
#define SNDCTL_DSP_COOKEDMODE   _SIOW ('P', 30, int)
#endif
void *mempool_alloc_small(size_t sizeofobject, unsigned int pool_id);
void mempool_free_small(unsigned int pool_id, int pool_unref_count);

typedef struct _oss_mmap_t {
    uint8_t *mmap_ptr;
    uint32_t size;
    uint32_t last_blocks;
    int32_t app_p;
    int snd_fd;
    uint8_t channels;
    fd_set writeset;
} oss_mmap_t;

void oss_mmap_close(void *_ao)
{
  oss_mmap_t *ao = (oss_mmap_t*)_ao;
  int tmp = 0;
  ioctl(ao->snd_fd, SNDCTL_DSP_SYNC);
  ioctl(ao->snd_fd, SNDCTL_DSP_SETTRIGGER, &tmp);
  munmap(ao->mmap_ptr, ao->size);
  close(ao->snd_fd);
}

void *oss_mmap_open(const char *devpath, uint32_t *samplerate, uint32_t frame_size, uint8_t channels)
{
  int tmp;
  unsigned int i;
  struct audio_buf_info info;
  void *buf;
  oss_mmap_t *ao = mempool_alloc_small(sizeof(oss_mmap_t), 2);
  ao->snd_fd = -1;

  if (!devpath) {
      devpath = "/dev/dsp";
  }

  if ((ao->snd_fd = open(devpath, O_RDWR, 0666)) == -1) {
      return NULL;
  }

  tmp = 0;
  ioctl(ao->snd_fd, SNDCTL_DSP_COOKEDMODE, &tmp);        /* Don't check the error return */

  tmp = AFMT_S16_LE;
  if (ioctl(ao->snd_fd, SNDCTL_DSP_SETFMT, &tmp) == -1) {
      return NULL;
  }
  if (tmp != AFMT_S16_LE) {
      return NULL;
  }

  if (channels == 2) {
    ao->channels = tmp = 2;                            /* Stereo */
  } else {
    ao->channels = tmp = 1;                            /* Mono */
  }
  if (ioctl(ao->snd_fd, SNDCTL_DSP_CHANNELS, &tmp) == -1) {
    return NULL;
  }

  if (frame_size > 1024) {
    tmp = ((16 << 16) | 13);
  } else {
    tmp = ((16 << 16) | 12);
  }
  tmp += (ao->channels >> 1);
  ioctl(ao->snd_fd, SNDCTL_DSP_SETFRAGMENT, &tmp);

  tmp = *samplerate;
  if (ioctl(ao->snd_fd, SNDCTL_DSP_SPEED, &tmp) == -1) {
      return NULL;
  }
  *samplerate = tmp;

  if (ioctl(ao->snd_fd, SNDCTL_DSP_GETOSPACE, &info) == -1) {
      return NULL;
  }
  ao->size = info.fragstotal * info.fragsize;
  ao->last_blocks = 0;

  if ((buf = mmap(NULL, ao->size, PROT_WRITE, MAP_FILE | MAP_SHARED, ao->snd_fd, 0)) == (void*)-1) {
      return NULL;
  }
  ao->mmap_ptr = buf;
  ao->app_p = 0;
#if 0
  for(i=0; i<ao->size; i++) {
    ao->mmap_ptr[i] = 0;
  }
#endif

  FD_ZERO(&ao->writeset);
  FD_SET(ao->snd_fd, &ao->writeset);

  tmp = 0;
  ioctl(ao->snd_fd, SNDCTL_DSP_SETTRIGGER, &tmp);
  tmp = PCM_ENABLE_OUTPUT;
  ioctl(ao->snd_fd, SNDCTL_DSP_SETTRIGGER, &tmp);
  return ao;
}

#define WORD2INT(x) ((x) < -32766.5f ? -32767 : ((x) > 32766.5f ? 32767 : lrintf(x)))
void oss_mmap_write_flt(void *_ao, float *buf, uint32_t bufsize)
{
  oss_mmap_t *ao = (oss_mmap_t*)_ao;
  int16_t *optr = (int16_t*)ao->mmap_ptr;
  size_t i;
  count_info ci;

  FD_ZERO(&ao->writeset);
  FD_SET(ao->snd_fd, &ao->writeset);

  select(ao->snd_fd+1, NULL, &ao->writeset, NULL, NULL);
  ioctl(ao->snd_fd, SNDCTL_DSP_GETOPTR, &ci);

  for (i=0; i<bufsize; i++) {
    optr[((ao->app_p + i) & ((ao->size-1) >> 1))] = WORD2INT(buf[i]*32768.0f);
  }
  ao->app_p += bufsize;
  ao->app_p &= ((ao->size-1) >> 1);
}

void oss_mmap_write_s16(void *_ao, int16_t *buf, uint32_t bufsize)
{
  oss_mmap_t *ao = (oss_mmap_t*)_ao;
  int16_t *optr = (int16_t*)ao->mmap_ptr;
  size_t i;
  count_info ci;

  FD_ZERO(&ao->writeset);
  FD_SET(ao->snd_fd, &ao->writeset);

  select(ao->snd_fd+1, NULL, &ao->writeset, NULL, NULL);
  ioctl(ao->snd_fd, SNDCTL_DSP_GETOPTR, &ci);

  for (i=0; i<bufsize; i++) {
    optr[((ao->app_p + i) & ((ao->size-1) >> 1))] = buf[i];
  }
  ao->app_p += bufsize;
  ao->app_p &= ((ao->size-1) >> 1);
}

