#ifndef __AUDIO_OUT_H__
#define __AUDIO_OUT_H__

#include <stdint.h>
#include <math.h>
#if defined(_WIN32) || defined(_WIN64)
#include "ntapi.h"
#endif

extern void (*audio_write_flt)(void *snd_fd, float *buf, uint32_t bufsize);
extern void (*audio_write_s16)(void *snd_fd, int16_t *buf, uint32_t bufsize);
extern void (*audio_close)(void *snd_fd);
#if defined(_WIN32) || defined(_WIN64)
typedef UNICODE_STRING devpath_t;
#else
typedef const char devpath_t;
#endif

void *audio_open(uint8_t devtype, devpath_t *devpath, uint32_t *samplerate, uint32_t bufsize, uint8_t channels);
void *wav_audio_open(devpath_t *devpath, uint32_t *samplerate, uint8_t channels);

void wav_audio_write_flt(void *snd_fd, float *buf, uint32_t bufsize);
void wav_audio_write_downmix_flt(void *snd_fd, float *buf, uint32_t bufsize);
void wav_audio_write_s16(void *snd_fd, int16_t *buf, uint32_t bufsize);
void wav_audio_write_downmix_s16(void *snd_fd, int16_t *buf, uint32_t bufsize);
void wav_audio_close(void *snd_fd);
void *md5sum_open(uint8_t nchannels);
void md5sum_write_flt(void *snd_fd, float *buf, uint32_t bufsize);
void md5sum_write_s16(void *snd_fd, int16_t *buf, uint32_t bufsize);
void md5sum_close(void *snd_fd);
void *oss_audio_open(const char *devpath, uint32_t *oss_audio_rate, uint8_t nchannels);
void oss_audio_write_flt(void *snd_fd, float *buf, uint32_t bufsize);
void oss_audio_write_s16(void *snd_fd, int16_t *buf, uint32_t bufsize);
void oss_audio_close(void *snd_fd);
void *alsa_audio_open(const char *devpath, uint32_t *samplerate, uint8_t channels, uint32_t *_ver);
void alsa_audio_write_flt(void *snd_fd, float *buf, uint32_t bufsize);
void alsa_audio_write_s16(void *snd_fd, int16_t *buf, uint32_t bufsize);
void alsa_audio_close(void *snd_fd);
void *alsa_mmap_open(const char *devpath, uint32_t *samplerate, uint32_t frame_size, uint8_t channels, uint32_t *_ver);
void alsa_mmap_write_flt(void *snd_fd, float *buf, uint32_t bufsize);
void alsa_mmap_write_s16(void *snd_fd, int16_t *buf, uint32_t bufsize);
void alsa_mmap_close(void *snd_fd);
void *oss_mmap_open(const char *devpath, uint32_t *samplerate, uint32_t frame_size, uint8_t channels);
void oss_mmap_write_flt(void *snd_fd, float *buf, uint32_t bufsize);
void oss_mmap_write_s16(void *snd_fd, int16_t *buf, uint32_t bufsize);
void oss_mmap_close(void *snd_fd);

void *CoreAudioOpen(uint32_t rate, uint8_t channels, uint8_t has_sbr);
void CoreAudioWriteFlt(void *_ao, float *output_samples, uint32_t bufsize);
void CoreAudioWriteS16(void *_ao, int16_t *output_samples, uint32_t bufsize);
void CoreAudioClose(void *_ao);

#if defined(_WIN32) || defined(_WIN64)
void *audio_wdmks_open(UNICODE_STRING *AudioDevicePath, uint32_t *samplerate, uint32_t bufsize, uint8_t channels);
void audio_wdmks_close(void *wdmks);
void *audio_winmm_open(unsigned int sfreq, unsigned char n_channels);
void audio_winmm_write_flt(void *waveout, float *buf, uint32_t bufsize);
void audio_winmm_write_s16(void *waveout, int16_t *buf, uint32_t bufsize);
void audio_winmm_close(void *waveout);
#endif

typedef struct TimeFilter {
    // Delay Locked Loop data. These variables refer to mathematical
    // concepts described in: http://www.kokkinizita.net/papers/usingdll.pdf
    double cycle_time;
    double feedback2_factor;
    double feedback3_factor;
    double clock_period;
    unsigned int count;
} TimeFilter;

/* exp(-x) using a 3-order power series */
static double qexpneg(double x)
{
    return 1 / (1 + x * (1 + 0.5*x * (1 + 0.333333333*x)));
}

/**
 * Create a new Delay Locked Loop time filter
 *
 * feedback2_factor and feedback3_factor are the factors used for the
 * multiplications that are respectively performed in the second and third
 * feedback paths of the loop.
 *
 * Unless you know what you are doing, you should set these as follow:
 *
 * o = 2 * M_PI * bandwidth * period_in_seconds
 * feedback2_factor = sqrt(2) * o
 * feedback3_factor = o * o
 *
 * Where bandwidth is up to you to choose. Smaller values will filter out more
 * of the jitter, but also take a longer time for the loop to settle. A good
 * starting point is something between 0.3 and 3 Hz.
 *
 * @param time_base   period of the hardware clock in seconds
 *                    (for example 1.0/44100)
 * @param period      expected update interval, in input units
 * @param brandwidth  filtering bandwidth, in Hz
 *
 * For more details about these parameters and background concepts please see:
 * http://www.kokkinizita.net/papers/usingdll.pdf
 */
static inline void timefilter_new(TimeFilter *self, double time_base, double period, double bandwidth)
{
    double o               = 2 * M_PI * bandwidth * period * time_base;
    self->clock_period     = time_base;
    self->count            = 0;
    self->feedback2_factor =  1.0 - qexpneg(M_SQRT2 * o);
    self->feedback3_factor = (1.0 - qexpneg(o * o)) / period;
}

/**
 * Update the filter
 *
 * This function must be called in real time, at each process cycle.
 *
 * @param period the device cycle duration in clock_periods. For example, at
 * 44.1kHz and a buffer size of 512 frames, period = 512 when clock_period
 * was 1.0/44100, or 512/44100 if clock_period was 1.
 *
 * system_time, in seconds, should be the value of the system clock time,
 * at (or as close as possible to) the moment the device hardware interrupt
 * occurred (or any other event the device clock raises at the beginning of a
 * cycle).
 *
 * @return the filtered time, in seconds
 */
double timefilter_update(TimeFilter *self, double system_time, double period);

/**
 * Evaluate the filter at a specified time
 *
 * @param delta  difference between the requested time and the current time
 *               (last call to ff_timefilter_update).
 * @return  the filtered time
 */
static inline double timefilter_eval(TimeFilter *self, double delta)
{
    return self->cycle_time + self->clock_period * delta;
}

/**
 * Reset the filter
 *
 * This function should mainly be called in case of XRUN.
 *
 * Warning: after calling this, the filter is in an undetermined state until
 * the next call to timefilter_update()
 */
static inline void timefilter_reset(TimeFilter *self)
{
    self->count = 0;
}

typedef struct AudioFifo {
    float *buffer;
    uint32_t rptr, wptr;
    uint32_t rndx, wndx, bufsize;
} AudioFifo;

static inline uint32_t fifo_size(AudioFifo *f)
{
    return (uint32_t)(f->wndx - f->rndx);
}

void fifo_alloc(AudioFifo *f, unsigned int size);
void fifo_free(AudioFifo *f);
unsigned int fifo_space(AudioFifo *f);
unsigned int fifo_write(AudioFifo *f, float *src, unsigned int size);
unsigned int fifo_write_interleave(AudioFifo *f, float *buf[2], unsigned int size, unsigned int ch);
unsigned int fifo_read(AudioFifo *f, void *dest, unsigned int buf_size);

#endif
