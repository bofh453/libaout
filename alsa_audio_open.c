#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include "alsa_pcm_api.h"
#define WORD2INT(x) ((x) < -32766.5f ? -32767 : ((x) > 32766.5f ? 32767 : lrintf(x)))
void alsa_init_hwparams(int snd_fd, snd_pcm_access_t access, uint32_t *samplerate, uint32_t frame_size, uint8_t channels);

void alsa_audio_close(void *ao)
{
    int snd_fd = (int)((size_t)ao);
    int _snd_fd = (snd_fd & 0x80FFFFFF);
    ioctl(_snd_fd, SNDRV_PCM_IOCTL_HW_FREE);
    close(_snd_fd);
}

void *alsa_audio_open(const char *devpath, uint32_t *samplerate, uint8_t channels, uint32_t *_ver)
{
    int ver, snd_fd = -1;

    if (!devpath) {
        devpath = "/dev/snd/pcmC0D0p";
    }

    snd_fd = open(devpath, O_WRONLY);
    if (snd_fd < 0)
        return NULL;

    if (ioctl(snd_fd, SNDRV_PCM_IOCTL_PVERSION, &ver) < 0) {
        if (snd_fd >= 0)
            close(snd_fd);
        return NULL;
    }
    if(_ver) *_ver = ver;

    // Initialize hwparams structure.
	alsa_init_hwparams(snd_fd, SND_PCM_ACCESS_RW_INTERLEAVED, samplerate, 1024, channels);
    snd_fd |= ((channels & 0x03) << 28);
    return (void*)((size_t)snd_fd);
}

void alsa_audio_write_flt(void *ao, float *buf, uint32_t bufsize)
{
    struct snd_xferi xferi;
    int snd_fd = (int)((size_t)ao);
    uint8_t alsa_channels = ((snd_fd >> 28) & 0x03);
    int _snd_fd = (snd_fd & 0x80FFFFFFUL);
	unsigned int i, j;
    short outbuf[8192];
    for(i=0; i<bufsize; i++) {
       	outbuf[i] = WORD2INT(buf[i]*32768.0f);
    }
    xferi.result = 0;
    xferi.buf = (char*) outbuf;
    xferi.frames = ((alsa_channels == 2) ? (bufsize >> 1) : bufsize);
    j = ioctl(_snd_fd, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &xferi);
	if (j >= 0) {
		j = xferi.result;
	}
    if(j == -32) { //-EPIPE
        ioctl(_snd_fd, SNDRV_PCM_IOCTL_PREPARE);
    }
}

void alsa_audio_write_s16(void *ao, int16_t *buf, uint32_t bufsize)
{
    struct snd_xferi xferi;
    int snd_fd = (int)((size_t)ao);
    uint8_t alsa_channels = ((snd_fd >> 28) & 0x03);
    int _snd_fd = (snd_fd & 0x80FFFFFFUL);
	unsigned int i, j;
    xferi.result = 0;
    xferi.buf = (char*) buf;
    xferi.frames = ((alsa_channels == 2) ? (bufsize >> 1) : bufsize);
    j = ioctl(_snd_fd, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &xferi);
	if (j >= 0) {
		j = xferi.result;
	}
    if(j == -32) { //-EPIPE
        ioctl(_snd_fd, SNDRV_PCM_IOCTL_PREPARE);
    }
}

