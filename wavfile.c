#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#if defined(_WIN32) || defined(_WIN64)
#include "ntapi.h"
#endif

static const unsigned char static_hdr_portion[20] = {
   0x52, 0x49, 0x46, 0x46, 0xFF, 0xFF, 0xFF, 0x7F,
   0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
   0x10, 0x00, 0x00, 0x00
};

typedef struct _WAVHeader {
    uint16_t wav_id;
    uint16_t channels;
    uint32_t samplerate;
    uint32_t bitrate;
    uint32_t block_align;
    uint32_t pad0;
    uint32_t pad1;
} __attribute__((packed)) WAVHeader;

static void write_wav_header(void *ao, uint32_t rate, uint8_t channels)
{
   WAVHeader w;
#if defined(_WIN32) || defined(_WIN64)
   IO_STATUS_BLOCK Iosb;
   NtWriteFile(ao, NULL, NULL, NULL, &Iosb, &static_hdr_portion, 20, NULL, NULL);
#else
   int fd = (int)((size_t)ao);
   write(fd, &static_hdr_portion, 20);
#endif

   w.wav_id = 3;
   w.channels = channels;
   w.samplerate = rate;
   w.bitrate = rate*channels*2;
   w.block_align = (channels << 1) | 0x00200000;
   w.pad0 = 0x61746164;
   w.pad1 = 0x7fffffff;
#if defined(_WIN32) || defined(_WIN64)
   NtWriteFile(ao, NULL, NULL, NULL, &Iosb, &w, sizeof(WAVHeader), NULL, NULL);
#else
   write(fd, &w, sizeof(WAVHeader));
#endif
}

#if defined(_WIN32) || defined(_WIN64)
void *wav_audio_open(UNICODE_STRING *devpath, uint32_t *samplerate, uint8_t channels)
#else
void *wav_audio_open(const char *devpath, uint32_t *samplerate, uint8_t channels)
#endif
{
#if defined(_WIN32) || defined(_WIN64)
	NTSTATUS r = STATUS_SUCCESS;
	HANDLE ao;
	IO_STATUS_BLOCK Iosb;
	UNICODE_STRING wavfile_name;
    OBJECT_ATTRIBUTES wav_oa;
    RtlDosPathNameToNtPathName_U(devpath->Buffer, &wavfile_name, NULL, NULL);
    memset(&wav_oa, 0, sizeof(wav_oa));
    wav_oa.Length = sizeof(wav_oa);
    wav_oa.RootDirectory = NULL;
    wav_oa.ObjectName = &wavfile_name;
    wav_oa.Attributes = OBJ_CASE_INSENSITIVE;
    NtCreateFile(&ao, FILE_GENERIC_WRITE|SYNCHRONIZE, &wav_oa, &Iosb,
                 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_ALL,
                 FILE_OVERWRITE_IF, 0x20, NULL, 0);
    RtlFreeUnicodeString(&wavfile_name);
#else
    void *ao = NULL;
	int snd_fd = open(devpath, O_WRONLY|O_CREAT, 0644);
	if (snd_fd < 0) {
		return NULL;
	}
    ao = (void*)((size_t)snd_fd);
#endif
    write_wav_header(ao, *samplerate, channels);
#if defined(_WIN32) || defined(_WIN64)
    ao = (HANDLE)((ULONG_PTR)ao | (channels & 0x03));
#else
    snd_fd |= ((channels & 0x03) << 28);
    ao = (void*)((size_t)snd_fd);
#endif
	return ao;
}

void wav_audio_write_flt(void *ao, float *buf, uint32_t bufsize)
{
#if defined(_WIN32) || defined(_WIN64)
	IO_STATUS_BLOCK Iosb;
    uint8_t audio_channels = ((ULONG_PTR)ao & 0x03);
	HANDLE _snd_fd = (HANDLE)((ULONG_PTR)ao & ~0x03ULL);
#else
    int snd_fd = (int)((size_t)ao);
    int _snd_fd = (snd_fd & 0x80FFFFFF);
#endif
#if defined(_WIN32) || defined(_WIN64)
    NtWriteFile(_snd_fd, NULL, NULL, NULL, &Iosb, buf, bufsize * 4, NULL, NULL);
#else
	write(_snd_fd, buf, bufsize * 4);
#endif
}

void wav_audio_write_downmix_flt(void *ao, float *buf, uint32_t bufsize)
{
#if defined(_WIN32) || defined(_WIN64)
	IO_STATUS_BLOCK Iosb;
	HANDLE _snd_fd = (HANDLE)((ULONG_PTR)ao & ~0x03ULL);
#else
    int snd_fd = (int)((size_t)ao);
    int _snd_fd = (snd_fd & 0x80FFFFFF);
#endif
	uint32_t i;
    float tmpbuf[16384];
    bufsize >>= 1;
    for (i=0; i<bufsize; i++) {
	    tmpbuf[i] = 0.5f * (buf[2*i] + buf[2*i+1]);
    }              
#if defined(_WIN32) || defined(_WIN64)
    NtWriteFile(_snd_fd, NULL, NULL, NULL, &Iosb, tmpbuf, bufsize * 4, NULL, NULL);
#else
	write(_snd_fd, tmpbuf, bufsize * 4);
#endif
}

void wav_audio_write_s16(void *ao, int16_t *buf, uint32_t bufsize)
{
#if defined(_WIN32) || defined(_WIN64)
	IO_STATUS_BLOCK Iosb;
    uint8_t audio_channels = ((ULONG_PTR)ao & 0x03);
	HANDLE _snd_fd = (HANDLE)((ULONG_PTR)ao & ~0x03ULL);
#else
    int snd_fd = (int)((size_t)ao);
    int _snd_fd = (snd_fd & 0x80FFFFFF);
#endif
    const float scale_s16toflt = (1.0f / 32768.0f); 
	float tmpbuf[8192];
	uint32_t i;
    for (i=0; i<bufsize; i++) {
	    tmpbuf[i] = ((float)buf[i] * scale_s16toflt);
    }              
#if defined(_WIN32) || defined(_WIN64)
    NtWriteFile(_snd_fd, NULL, NULL, NULL, &Iosb, tmpbuf, bufsize * 4, NULL, NULL);
#else
	write(_snd_fd, tmpbuf, bufsize * 4);
#endif
}

void wav_audio_write_downmix_s16(void *ao, int16_t *buf, uint32_t bufsize)
{
#if defined(_WIN32) || defined(_WIN64)
	IO_STATUS_BLOCK Iosb;
	HANDLE _snd_fd = (HANDLE)((ULONG_PTR)ao & ~0x03ULL);
#else
    int snd_fd = (int)((size_t)ao);
    int _snd_fd = (snd_fd & 0x80FFFFFF);
#endif
    const float scale_s16toflt = (1.0f / 32768.0f); 
	float tmpbuf[8192];
	uint32_t i;
    bufsize >>= 1;
    for (i=0; i<bufsize; i++) {
        float f = ((float)buf[2*i] * scale_s16toflt);
        float g = ((float)buf[2*i+1] * scale_s16toflt);
        tmpbuf[i] = 0.5f * (f + g);
    }              
#if defined(_WIN32) || defined(_WIN64)
    NtWriteFile(_snd_fd, NULL, NULL, NULL, &Iosb, tmpbuf, bufsize * 4, NULL, NULL);
#else
	write(_snd_fd, tmpbuf, bufsize * 4);
#endif
}

void wav_audio_close(void *ao)
{
#if defined(_WIN32) || defined(_WIN64)
	HANDLE _snd_fd = (HANDLE)((ULONG_PTR)ao & ~0x03ULL);
	NtClose(_snd_fd);
#else
    int snd_fd = (int)((size_t)ao);
    int _snd_fd = (snd_fd & 0x80FFFFFF);
    close(_snd_fd);
#endif
}

