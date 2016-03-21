#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "audio_out.h"

void (*audio_write_flt)(void *snd_fd, float *buf, uint32_t bufsize);
void (*audio_write_s16)(void *snd_fd, int16_t *buf, uint32_t bufsize);
void (*audio_close)(void *snd_fd);

void dummy_write_flt(void *_ao, float *buf, uint32_t sz)
{
}

void dummy_write_s16(void *_ao, int16_t *buf, uint32_t sz)
{
}

void dummy_audio_close(void *_ao)
{
}

double timefilter_update(TimeFilter *self, double system_time, double period)
{
    self->count++;
    if (self->count == 1) {
        self->cycle_time = system_time;
    } else {
        double cycle_time, loop_error;
        self->cycle_time += self->clock_period * period;
        loop_error = system_time - self->cycle_time;

        cycle_time = (1.0 / self->count);
        if (self->feedback2_factor > cycle_time) cycle_time = self->feedback2_factor;
        self->cycle_time   += cycle_time * loop_error;
        self->clock_period += self->feedback3_factor * loop_error;
    }
    return self->cycle_time;
}

void *audio_open(uint8_t devtype, devpath_t *devpath, uint32_t *samplerate, uint32_t bufsize, uint8_t channels)
{
    void *ao = NULL;
    uint8_t downmix = (channels >> 7);
    channels &= 0x7F;
#ifdef __linux__
    if (devtype == 'a') goto try_alsa;
#endif
#if !defined(_WIN32) && !defined(_WIN64)
    if (devtype == 'o') goto try_oss;
#endif
#if (defined(_WIN32) || defined(_WIN64))
    if ((devtype == 's') || (devtype == 'S')) goto try_nt_wdmks;
#ifdef ENABLE_WINMM
    if (devtype == 'm') goto try_winmm;
#endif
#endif
    if ((devtype == 'w') || (devtype == 'f')) {
        if(!(ao = wav_audio_open(devpath, samplerate, downmix ? 1 : channels))) {
            //audio_wrerr("Cannot open sound device (file), exiting.\n");
            audio_write_flt = dummy_write_flt;
            audio_write_s16 = dummy_write_s16;
            audio_close = dummy_audio_close;
            return NULL;
        }
        audio_write_flt = wav_audio_write_flt;
        audio_write_s16 = wav_audio_write_s16;
        audio_close = wav_audio_close;
        if (downmix && (channels != 1)) {
            audio_write_flt = wav_audio_write_downmix_flt;
            audio_write_s16 = wav_audio_write_downmix_s16;
        }
        return ao;
    } else if (devtype == '5') {
        if(!(ao = md5sum_open(channels))) {
            //audio_wrerr("Cannot open sound device (MD5 hash), exiting.\n");
            audio_write_flt = dummy_write_flt;
            audio_write_s16 = dummy_write_s16;
            audio_close = dummy_audio_close;
            return NULL;
        }
        audio_write_flt = md5sum_write_flt;
        audio_write_s16 = md5sum_write_s16;
        audio_close = md5sum_close;
        return ao;
    } else {
#ifdef __linux__
    if (!ao) {
try_alsa:
        ao = alsa_audio_open(devpath, samplerate, channels, NULL);
        if (ao) {
            audio_write_flt = alsa_audio_write_flt;
            audio_write_s16 = alsa_audio_write_s16;
            audio_close = alsa_audio_close;
            return ao;
        }
    }
#ifdef ENABLE_MMAP
    if (!ao) {
        ao = alsa_mmap_open(devpath, samplerate, bufsize, channels, NULL);
        if (ao) {
            audio_write_flt = alsa_mmap_write_flt;
            audio_write_s16 = alsa_mmap_write_s16;
            audio_close = alsa_mmap_close;
            return ao;
        }
    }
#endif
#endif
#if !defined(_WIN32) && !defined(_WIN64)
    if (!ao) {
try_oss:
        ao = oss_audio_open(devpath, samplerate, channels);
        if (ao) {
            audio_write_flt = oss_audio_write_flt;
            audio_write_s16 = oss_audio_write_s16;
            audio_close = oss_audio_close;
            return ao;
        }
    }
#ifdef ENABLE_MMAP
    if (!ao) {
        ao = oss_mmap_open(devpath, samplerate, bufsize, channels);
        if (ao) {
            audio_write_flt = oss_mmap_write_flt;
            audio_write_s16 = oss_mmap_write_s16;
            audio_close = oss_mmap_close;
            return ao;
        }
    }
#endif
#endif
#if (defined(_WIN32) || defined(_WIN64))
    if (!ao) {
try_nt_wdmks:
        ao = audio_wdmks_open(devpath, samplerate, bufsize, channels);
        if (ao) {
            audio_close = audio_wdmks_close; // audio_wdmks_open will already have initialized audio_write for us.
            return ao;
        }
    }
#ifdef ENABLE_WINMM
    if (!ao) {
try_winmm:
        ao = audio_winmm_open(*samplerate, channels);
        if (ao) {
            audio_write_flt = audio_winmm_write_flt;
            audio_write_s16 = audio_winmm_write_s16;
            audio_close = audio_winmm_close;
            return ao;
        }
    }
#endif
#endif
        if (!ao) {
            //audio_wrerr("Tried all sound devices, none were successfully opened. Exiting...\n");
            audio_write_flt = dummy_write_flt;
            audio_write_s16 = dummy_write_s16;
            audio_close = dummy_audio_close;
            return NULL;
        }
    }
    return ao;
}

