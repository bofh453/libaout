/*
 * NT/WDMKS (Kernel Streaming) audio output routines.
 *
 * This is the lowest-level audio output code possible for Windows.
 * It needs absolutely nothing from userland, and only KS.SYS/PORTCLS.SYS
 * and your soundcard's particular port/miniport driver present in order to work.
 * (So yes, it will work on Windows XP if you nuke all of kmixer/wdmaud/etc,
 *  and similarly it will work on Windows 7 if you stop both the Windows Audio service
 *  and the Windows Audio Endpoint Mapper service).
 *
 * Furthermore, it is extremely low-latency. This comes at a price:
 * Whatever thread is playing audio via this method basically has to be at realtime priority
 * (i.e. base priority set to 24) in order for there to not be an unlistenable amount of audio dropouts.
 * (Sadly Microsoft seems to think giving only administrators SE_INC_PROCESS_BASE_PRIORITY_PRIVILEGE
 *  is a good idea. Edit your local security policy to reflect something more sane).
 * (In the event that you cannot set this to realtime priority, at least elevate the process/thread
 *  priority as much as you can: going to base priority 13 does not require special privileges
 *  and should often suffice, at least mostly).
 *
 * This code is still fairly experimental, and moreover because it's so low-level there's
 * a lot of opportunity for device-specific bugs.
 * For instance, unlistenable artifacts are generated with one particular model of Realtek codec
 * (the underlying device being hda_intel, of course).
 *
 * Finally, a lot of hda_intel drivers claim the card cannot support mono playback.
 * Most chipsets actually DO (the only ones that don't seem to use Analog Devices codecs, sadly),
 * but the driver still won't instantiate a pin for them.
 * Should handle this somewhat sanely in the future. Probably set it to stereo and just have it
 * interleave the same channel of samples into the audio output buffer.
 *
 * TODO:
 *  - More testing, with as many devices as possible.
 *  - Support KSPROPERTY_RTAUDIO_POSITIONREGISTER, literally the one useful feature introduced
 *    in the hda_intel spec for which support is mandated on any complying card is that of
 *    a memory-mappable audio status register. This would literally cut context switches
 *    in audio_wdmks_play_wavert() in half whenever it could be used, which would appear to be often.
 *  - Better/more resilient WavePCI/WaveCyclic audio output routines.
 *  - Dynamically compute WaveRT timeouts in polled mode based on returned values in IO_STATUS_BLOCK,
 *    hopefully this will make polled mode less of a buffer underrun/overflow mess.
 *    (Which it currently is. Thankfully everything seems to support notification so eh).
 *  - More comments re: odd quirks of soundcards/PORTCLS/etc.
 *
 * @author Peter Barfuss ( pbarfuss uwaterloo ca)
 */

#define _UNICODE
#define UNICODE
//#define _KSDDK_

#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <math.h>
#include "ntapi.h"
#include <ks.h>
#include "ksmedia.h"
#ifndef COMPILE_NATIVE_BINARY
#include <wincon.h>
#endif
int vsnprintf(char *buf, size_t lim, register const char * __restrict fmt, va_list ap);
#define NT_PFX L"\\GLOBAL?"

#ifndef WAVE_FORMAT_PCM
#define WAVE_FORMAT_PCM 1
#endif

#ifndef _WAVEFORMATEX_
#define _WAVEFORMATEX_
typedef struct tWAVEFORMATEX {
    WORD wFormatTag;
    WORD nChannels;
    DWORD nSamplesPerSec;
    DWORD nAvgBytesPerSec;
    WORD nBlockAlign;
    WORD wBitsPerSample;
    WORD cbSize;
} WAVEFORMATEX,*PWAVEFORMATEX,NEAR *NPWAVEFORMATEX,*LPWAVEFORMATEX;
#endif

typedef struct {
  GUID Set;
  ULONG Id;
  ULONG Flags;
} _KSIDENTIFIER;

typedef struct {
  _KSIDENTIFIER Interface;
  _KSIDENTIFIER Medium;
  ULONG PinId;
  HANDLE PinToHandle;
  KSPRIORITY Priority;
} _KSPIN_CONNECT;

#undef KSSTRING_Pin
#define KSSTRING_Pin   L"{146F1A80-4791-11D0-A5D6-28DB04C10000}\\"
static const GUID _KSPROPSETID_Pin                      = {0x8C134960L, 0x51AD, 0x11CF, {0x87, 0x8A, 0x94, 0xF8, 0x01, 0xC1, 0x00, 0x00}};
static const GUID _KSPROPSETID_Connection               = {0x1D58C920L, 0xAC9B, 0x11CF, {0xA5, 0xD6, 0x28, 0xDB, 0x04, 0xC1, 0x00, 0x00}};
static const GUID _KSPROPSETID_General                  = {0x1464EDA5L, 0x6A8F, 0x11D1, {0x9A, 0xA7, 0x00, 0xA0, 0xC9, 0x22, 0x31, 0x96}};
static const GUID _KSPROPSETID_Audio                    = {0x45FFAAA0L, 0x6E1B, 0x11D0, {0xBC,0xF2,0x44,0x45,0x53,0x54,0x00,0x00}};
static const GUID _KSPROPSETID_RtAudio                  = {0xa855a48c, 0x2f78, 0x4729, {0x90,0x51,0x19,0x68,0x74,0x6b,0x9e,0xef}};
#define _KSINTERFACESETID_Standard {0x1A8766A0L, 0x62CE, 0x11CF, {0xA5, 0xD6, 0x28, 0xDB, 0x04, 0xC1, 0x00, 0x00}}
#define _KSMEDIUMSETID_Standard    {0x4747B320L, 0x62CE, 0x11CF, {0xA5, 0xD6, 0x28, 0xDB, 0x04, 0xC1, 0x00, 0x00}}
static const _KSPIN_CONNECT _PinConnect = { { _KSINTERFACESETID_Standard, 1, 0}, { _KSMEDIUMSETID_Standard, 0, 0 }, 0, NULL, { KSPRIORITY_NORMAL, 1 } };
static const KSDATAFORMAT KsDataFormat = { 64, 0, 0, 0,
                                           {0x73647561L, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71}},
                                           {0x00000001L, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71}},
                                           {0x05589f81L, 0xc356, 0x11ce, {0xbf, 0x01, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a}}};

typedef struct _nt_wdmks_t {
    HANDLE FilterHandle;
    HANDLE EventHandle;
    HANDLE PinHandle;
    uint32_t SampleRate;
    BOOLEAN PinNotificationSupport;
    int16_t *WaveRTBuf;
    uint32_t WaveRTBufSize;
    LARGE_INTEGER WaveRTPollTimeout;
    BOOLEAN IsWavePCI;
    DWORD WavePCIWritePtr;
    KSSTREAM_HEADER Packet[4];
    HANDLE WavePCIEvents[4];
    unsigned char init;
    unsigned char packets_used, packets_total;
    unsigned char EventSignalled;
} nt_wdmks_t;

typedef struct {
  WCHAR KSString_Pin[39];
  _KSPIN_CONNECT PinConnect;
  KSDATAFORMAT DataFormat;
  WAVEFORMATEX WaveFormatEx;
} __attribute__((gcc_struct, packed)) KSPINCONNECT_DATAFORMAT;

static uint16_t nt_wdmks_utf8_to_ucs2(char *utf8, uint32_t *len)
{
  if ((utf8[0] & 0x80) == 0x00) {
      *len = 1;
      return utf8[0];
  }
  else if ((utf8[0] & 0xe0) == 0xc0 &&
           (utf8[1] & 0xc0) == 0x80) {
      *len = 2;
      return (((utf8[0] & 0x1fL) << 6) | ((utf8[1] & 0x3fL) << 0));
  }
  else if ((utf8[0] & 0xf0) == 0xe0 &&
           (utf8[1] & 0xc0) == 0x80 &&
           (utf8[2] & 0xc0) == 0x80) {
      *len = 3;
      return (((utf8[0] & 0x0fL) << 12) | ((utf8[1] & 0x3fL) <<  6) | ((utf8[2] & 0x3fL) <<  0));
  }
  *len = 0;
  return 0xFFFD;
}

int nt_printf(const char *fmt, ...) {
    unsigned int i = 0, j = 0;
    wchar_t wbuf[1024];
    char buf[1024];
    va_list arg;
    int rv;
#ifdef COMPILE_NATIVE_BINARY
#ifdef CAN_USE_NTDISPLAYSTRING
    UNICODE_STRING outstr;
#endif
#else
    HANDLE errh = RtlGetConsoleHandle();
    DWORD done;
#endif

    va_start(arg, fmt);
    rv = vsnprintf(buf, 4095, fmt, arg);
    va_end(arg);

    while (i < rv) {
        unsigned int wclen;
        wbuf[j++] = nt_wdmks_utf8_to_ucs2(buf+i, &wclen);
        i += wclen;
    }
    wbuf[j++] = L'\0';

#ifdef COMPILE_NATIVE_BINARY
#ifdef CAN_USE_NTDISPLAYSTRING
    RtlInitUnicodeString(&outstr, wbuf);
    NtDisplayString(&outstr);
#endif
#else
    WriteConsoleW(errh, wbuf, rv, &done, NULL);
#endif
    return rv;
}

static unsigned long nt_wdmks_pow2_gcd(unsigned long expt, unsigned long v) {
     unsigned long k = 0;
     if (v == 0)
         return (1U << expt);
     while ((k < expt) && ((v & 1) == 0)) { /* while v is even and k < expt, where 2^expt = u */
         v >>= 1;   /* shift v right, dividing it by 2 */
         k++;       /* add a power of 2 to the final result */
     }
     return k;  /* returns just k, so we can later just use a shift to divide */
}

/*
 * This function will handle getting the cyclic buffer from a WaveRT driver.
 * Certain WaveRT drivers needs to have requested buffer size on multiples of 128 bytes.
 *
 * bofh note: what drivers? I've yet to run into one that crappy.
 * ...I hope I never do.
 */
static unsigned long PinGetBuffer(HANDLE hPin, BOOLEAN notify_supported, ULONG BlockAlign,
                                  void** pBuffer, uint32_t* pRequestedBufSize)
{
    unsigned long result = 0;
    KSRTAUDIO_BUFFER_PROPERTY_WITH_NOTIFICATION propInNotify;
    KSRTAUDIO_BUFFER_PROPERTY propInPolled;
    KSRTAUDIO_BUFFER propOut;
    IO_STATUS_BLOCK Iosb;

    propInNotify.BaseAddress = NULL;
    propInNotify.NotificationCount = 2;
    propInNotify.RequestedBufferSize = *pRequestedBufSize;
    propInNotify.Property.Set = _KSPROPSETID_RtAudio;
    propInNotify.Property.Id = KSPROPERTY_RTAUDIO_BUFFER_WITH_NOTIFICATION;
    propInNotify.Property.Flags = KSPROPERTY_TYPE_GET;
    propInPolled.BaseAddress = NULL;
    propInPolled.RequestedBufferSize = *pRequestedBufSize;
    propInPolled.Property.Set = _KSPROPSETID_RtAudio;
    propInPolled.Property.Id = KSPROPERTY_RTAUDIO_BUFFER;
    propInPolled.Property.Flags = KSPROPERTY_TYPE_GET;

    while (1) {
        if (notify_supported == TRUE) {
            /* In case of unknown (or notification), we try both modes */
            result = NtDeviceIoControlFile(hPin, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                                           &propInNotify, sizeof(KSRTAUDIO_BUFFER_PROPERTY_WITH_NOTIFICATION),
                                           &propOut, sizeof(KSRTAUDIO_BUFFER));
            if (result == 0) {
                *pBuffer = propOut.BufferAddress;
                *pRequestedBufSize = propOut.ActualBufferSize;
                nt_printf("Got buffer (with notification), size: 0x%lx\n", *pRequestedBufSize);
                break;
            }
            nt_printf("Error: no notification support, trying a polled buffer...\n");
        }

        /* Notification unsupported for whatever reason. Yuck. Try getting a buffer anyway and polling instead. */
        result = NtDeviceIoControlFile(hPin, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                                       &propInPolled, sizeof(KSRTAUDIO_BUFFER_PROPERTY),
                                       &propOut, sizeof(KSRTAUDIO_BUFFER));
        if (result == 0) {
            *pBuffer = propOut.BufferAddress;
            *pRequestedBufSize = propOut.ActualBufferSize;
            nt_printf("Got buffer (polled), size: 0x%lx\n", *pRequestedBufSize);
            break;
        }

        /* Check if requested size is on a 128 byte boundary */
        if (((SIZE_T)(*pRequestedBufSize) & 127UL) == 0) {
            nt_printf("Buffer size on 128 byte boundary, still fails :(\n");
            /* Ok, can't do much more */
            break;
        } else {
            /* Compute LCM so we know which sizes are on a 128 byte boundary */
            const unsigned gcd = nt_wdmks_pow2_gcd(7, nBlockAlign);
            const unsigned lcm = (BlockAlign >> (7-gcd));
            DWORD dwOldSize = *pRequestedBufSize;

            /* Align size to (next larger) LCM byte boundary, and then we try again.
             * Note that LCM is not necessarily a power of 2.
             */
            *pRequestedBufSize = ((*pRequestedBufSize + lcm - 1) / lcm) * lcm;
            nt_printf("Adjusting buffer size from %lu to %lu bytes (128 byte boundary, LCM=%u)\n", dwOldSize, *pRequestedBufSize, lcm);
        }
    }

    return result;
}
#define A(dev) ((KSDATARANGE_AUDIO*)dev)
void audio_wdmks_write_wavepci_flt(void *wdmks, float *buf, uint32_t Length);
void audio_wdmks_write_wavepci_s16(void *wdmks, int16_t *buf, uint32_t Length);
void audio_wdmks_write_wavert_flt(void *wdmks, float *buf, uint32_t Length);
void audio_wdmks_write_wavert_s16(void *wdmks, int16_t *buf, uint32_t Length);
extern void (*audio_write_flt)(void *wdmks, float *floatbuf, uint32_t Length);
extern void (*audio_write_s16)(void *wdmks, int16_t *floatbuf, uint32_t Length);

void *audio_wdmks_open(UNICODE_STRING *AudioDevicePath, uint32_t *srate, uint32_t bufsize, uint8_t channels)
{
    KSP_PIN ksPProp;
    KSPINCONNECT_DATAFORMAT PinConnect;
    KSSTATE State;
    KSPROPERTY Property;
    DWORD PinCount;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING PinName;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS r;
    ULONG BufferSize = sizeof(KSPINCONNECT_DATAFORMAT);
    SIZE_T i, sz;
    nt_wdmks_t *s = NULL;
    uint32_t samplerate = *srate;

    /* First, allocate WDMKS structure. */
    sz = sizeof(nt_wdmks_t);
    NtAllocateVirtualMemory(((HANDLE)-1), (void**)&s, 0, &sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    /* Open a handle to the device. */
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = AudioDevicePath;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    r = NtCreateFile(&(s->FilterHandle), FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &oa, &Iosb,
                     0, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, 0, 0);
    if (r != STATUS_SUCCESS) {
        nt_printf("NtCreateFile (KsOpenFilter) failed: 0x%lx\n", r);
        return NULL;
    }

    r = NtCreateEvent(&(s->EventHandle), EVENT_ALL_ACCESS, NULL, 1, FALSE);
    if (r != STATUS_SUCCESS) {
        nt_printf("NtCreateEvent failed: 0x%lx\n", r);
        return NULL;
    }

    ksPProp.Property.Set = _KSPROPSETID_Pin;
    ksPProp.Property.Id = KSPROPERTY_PIN_CTYPES;
    ksPProp.Property.Flags = KSPROPERTY_TYPE_GET;
    ksPProp.PinId = 0;
    ksPProp.Reserved = 0;
    NtDeviceIoControlFile(s->FilterHandle, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                          &ksPProp, sizeof(KSP_PIN), &PinCount, sizeof(PinCount));

    /* Setup the KS Pin Data. */
    memcpy(&(PinConnect.KSString_Pin), KSSTRING_Pin, 39 * sizeof(WCHAR));
    memcpy(&(PinConnect.PinConnect), &_PinConnect, sizeof(_KSPIN_CONNECT));

    /* Setup the KS Data Format Information. */
    PinConnect.WaveFormatEx.wFormatTag = WAVE_FORMAT_PCM;
    PinConnect.WaveFormatEx.nChannels = channels;
    PinConnect.WaveFormatEx.nSamplesPerSec = samplerate;
    PinConnect.WaveFormatEx.nBlockAlign = 4;
    PinConnect.WaveFormatEx.nAvgBytesPerSec = samplerate * channels * 2;
    PinConnect.WaveFormatEx.wBitsPerSample = 16;
    PinConnect.WaveFormatEx.cbSize = 0;
    memcpy(&(PinConnect.DataFormat), &KsDataFormat, sizeof(KSDATAFORMAT));
    PinConnect.DataFormat.FormatSize += sizeof(WAVEFORMATEX);

    /* Create the pin.
     *
     * Yes, folks, this is all that KsCreatePin() does. It's an IRP_MJ_CREATE call,
     * which in Windows is implemented via a call to NtCreateFile,
     * and creates a special file corresponding to the instantiated pin/device node on the soundcard.
     */
    PinName.Buffer = (LPWSTR)&PinConnect;
    PinName.Length = PinName.MaximumLength = BufferSize;

    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.RootDirectory = s->FilterHandle;
    oa.ObjectName = &PinName;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    r = NtCreateFile(&(s->PinHandle), GENERIC_WRITE, &oa, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_ALL, 1, 0, NULL, 0);
    if (r != STATUS_SUCCESS) {
        nt_printf("NtCreateFile (KsCreatePin) failed: 0x%lx\n", r);
        return NULL;
    }

    /* Find out some things about the pin. */
    Property.Set = _KSPROPSETID_RtAudio;
    Property.Id = 8; /* = KSPROPERTY_RTAUDIO_QUERY_NOTIFICATION_SUPPORT */
    Property.Flags = KSPROPERTY_TYPE_GET;
    NtDeviceIoControlFile(s->PinHandle, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                          &Property, sizeof(KSPROPERTY), &(s->PinNotificationSupport), sizeof(BOOL));
    nt_printf("PinQueryNotificationSupport: notification %s\n", (s->PinNotificationSupport ? "supported" : "not supported"));

    /* Get the WaveRT cyclic buffer. */
    s->WaveRTBufSize = bufsize;
    r = PinGetBuffer(s->PinHandle, s->PinNotificationSupport, PinConnect.WaveFormatEx.nBlockAlign,
                     (VOID**)&(s->WaveRTBuf), &(s->WaveRTBufSize));
    if (r != STATUS_SUCCESS) {
        KSALLOCATOR_FRAMING ksaf;
        SIZE_T WavePCIBufSize = bufsize;
        nt_printf("PinGetBuffer failed: 0x%x\n", r);

        /* It's possible this is still a WaveRT device with the finickiest DMA buffer on the planet,
         * but more likely it's just a WavePCI/WaveCyclic device instead. So let's set the audio output
         * function pointer appropriately, and finish device init as a WavePCI device.
         * (and if that fails, something is *seriously* wrong).
         */
        nt_printf("It's possible that this is not a WaveRT device, attempting to access it as a WaveCyclic/WavePCI device instead...\n");
        audio_write_flt = audio_wdmks_write_wavepci_flt;
        audio_write_s16 = audio_wdmks_write_wavepci_s16;
        Property.Set = _KSPROPSETID_Connection;
        Property.Id = KSPROPERTY_CONNECTION_ALLOCATORFRAMING;
        Property.Flags = KSPROPERTY_TYPE_GET;
        r = NtDeviceIoControlFile(s->PinHandle, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                                  &Property, sizeof(KSPROPERTY), &ksaf, sizeof(KSALLOCATOR_FRAMING));
        if (r != STATUS_SUCCESS) {
            nt_printf("Error: request for framing parameters failed: 0x%lx\n", r);
        } else {
            nt_printf("KSALLOCATOR_FRAMING: Frames: 0x%lx, FrameSize: 0x%lx\n", ksaf.Frames, ksaf.FrameSize);
        }
        WavePCIBufSize = ksaf.Frames * bufsize;
        r = NtAllocateVirtualMemory(((HANDLE)-1), (void**)&(s->WaveRTBuf), 0, &WavePCIBufSize,
                                    MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (r != STATUS_SUCCESS) {
            nt_printf("Error: unable to allocate WavePCI/WaveCyclic ringbuffer: 0x%lx\n", r);
            return NULL;
        }
        for (i = 0; i < 4; i++) {
            memset(&s->Packet[i], 0, sizeof(KSSTREAM_HEADER));
            s->Packet[i].Data = ((uint8_t*)s->WaveRTBuf + i*bufsize);
            s->Packet[i].FrameExtent = bufsize;
            s->Packet[i].DataUsed = bufsize;
            s->Packet[i].Size = sizeof(KSSTREAM_HEADER);
            r = NtCreateEvent(&(s->WavePCIEvents[i]), EVENT_ALL_ACCESS, NULL, 1, FALSE);
            if (r != 0) {
                nt_printf("NtCreateEvent failed: 0x%lx\n", r);
                return NULL;
            }
        }
        s->IsWavePCI = TRUE;
        s->packets_used = 0;
        s->packets_total = 4;
        s->EventSignalled = 0;
        s->init = 0;
        //s->WaveRTBufSize = (ksaf.Frames * (bufsize >> 1));
        s->WaveRTBufSize = (bufsize >> 1);
        s->WavePCIWritePtr = 0;
        goto set_state_to_run;
    }
    audio_write_flt = audio_wdmks_write_wavert_flt;
    audio_write_s16 = audio_wdmks_write_wavert_s16;

    /* If we have notification support, register a handler. */
    if (s->PinNotificationSupport) {
        KSRTAUDIO_NOTIFICATION_EVENT_PROPERTY prop;
        prop.NotificationEvent = s->EventHandle;
        prop.Property.Set = _KSPROPSETID_RtAudio;
        prop.Property.Id = KSPROPERTY_RTAUDIO_REGISTER_NOTIFICATION_EVENT;
        prop.Property.Flags = KSPROPERTY_TYPE_GET;

        r = NtDeviceIoControlFile(s->PinHandle, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                                  &prop, sizeof(KSRTAUDIO_NOTIFICATION_EVENT_PROPERTY),
                                  &prop, sizeof(KSRTAUDIO_NOTIFICATION_EVENT_PROPERTY));
        if (r != STATUS_SUCCESS) {
            nt_printf("Error: failed to register notification event handle 0x%lx: 0x%lx\n", s->EventHandle, r);
        }
    } else {
        /* Otherwise, determine polling timeout.
         *
         * An AAC frame is either 4K, 8K or 16K (floating-point).
         * The soundcard doesn't actually accept that, it takes s16le instead.
         * So that means either 2K, 4K or 8K.
         * The buffer for WaveRT is double that size, i.e. either 4K, 8K or 16K (again).
         * We want to timeout when the buffer is half-full, mirroring what WaveRT notification does.
         * Therefore, we want to timeout at (bufsize >> 1)/samplerate seconds.
         * Now, NtWaitForSingleObject() takes timeout values in units of microseconds.
         * (In a bizarre leap of common sense, considering that a lot of NT kernel APIs use 100s of ns instead).
         * Note that the value must be negative so that it's treated as a relative timeout:
         * Positive timeout values get treated as absolute timeouts, which are most certainly not what we want.
         */
        s->WaveRTPollTimeout.QuadPart = -(1000000LL * (bufsize >> 0))/samplerate;
    }

set_state_to_run:
    /* Init KSPROPERTY struct. */
    Property.Set = _KSPROPSETID_Connection;
    Property.Id = KSPROPERTY_CONNECTION_STATE;
    Property.Flags = KSPROPERTY_TYPE_SET;

    /* Change the state to run. */
    State = KSSTATE_ACQUIRE;
    r = NtDeviceIoControlFile(s->PinHandle, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                              &Property, sizeof(KSPROPERTY), &State, sizeof(State));
    if (r != STATUS_SUCCESS) {
        nt_printf("Unable to set WaveRT state to KSSTATE_ACQUIRE: 0x%lx\n", r);
    }
    State = KSSTATE_RUN;
    r = NtDeviceIoControlFile(s->PinHandle, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                              &Property, sizeof(KSPROPERTY), &State, sizeof(State));
    if (r != STATUS_SUCCESS) {
        nt_printf("Unable to set WaveRT state to KSSTATE_RUN: 0x%lx\n", r);
    }
    return s;
}

#define WORD2INT(x) ((x) < -32766.5f ? -32767 : ((x) > 32766.5f ? 32767 : lrintf(x)))
void audio_wdmks_write_wavepci_flt(void *wdmks, float *buf, uint32_t Length) {
    nt_wdmks_t *s = (nt_wdmks_t *)wdmks;
    NTSTATUS r = STATUS_SUCCESS;
    SIZE_T k;
    IO_STATUS_BLOCK Iosb;

    if ((s->packets_used < s->packets_total) && !s->init) {
        for (k = 0; k < Length; k++) {
            s->WaveRTBuf[s->packets_used * s->WaveRTBufSize + k] = WORD2INT(buf[k]*32768.0f);
        }
        NtDeviceIoControlFile(s->PinHandle, s->WavePCIEvents[s->packets_used], NULL, NULL, &Iosb,
                               IOCTL_KS_WRITE_STREAM, NULL, 0, &s->Packet[s->packets_used], sizeof(KSSTREAM_HEADER));
        s->packets_used++;
        return;
    }

    r = NtWaitForMultipleObjects(4, s->WavePCIEvents, WaitAny, FALSE, NULL);
    s->EventSignalled = r - WAIT_OBJECT_0;
    s->packets_used--;

    for (k = 0; k < Length; k++) {
        s->WaveRTBuf[s->EventSignalled * s->WaveRTBufSize + k] = WORD2INT(buf[k]*32768.0f);
    }
    NtDeviceIoControlFile(s->PinHandle, s->WavePCIEvents[s->EventSignalled], NULL, NULL, &Iosb,
                          IOCTL_KS_WRITE_STREAM, NULL, 0, &s->Packet[s->EventSignalled], sizeof(KSSTREAM_HEADER));
    s->packets_used++;
    if ((s->packets_used == s->packets_total) && !s->init) {
        s->init = 1;
    }
}

void audio_wdmks_write_wavepci_s16(void *wdmks, int16_t *buf, uint32_t Length) {
    nt_wdmks_t *s = (nt_wdmks_t *)wdmks;
    NTSTATUS r = STATUS_SUCCESS;
    IO_STATUS_BLOCK Iosb;

    if ((s->packets_used < s->packets_total) && !s->init) {
        memcpy(&s->WaveRTBuf[s->packets_used * s->WaveRTBufSize], buf, (Length * sizeof(int16_t)));
        NtDeviceIoControlFile(s->PinHandle, s->WavePCIEvents[s->packets_used], NULL, NULL, &Iosb,
                               IOCTL_KS_WRITE_STREAM, NULL, 0, &s->Packet[s->packets_used], sizeof(KSSTREAM_HEADER));
        s->packets_used++;
        return;
    }

    r = NtWaitForMultipleObjects(4, s->WavePCIEvents, WaitAny, FALSE, NULL);
    s->EventSignalled = r - WAIT_OBJECT_0;
    s->packets_used--;

    memcpy(&s->WaveRTBuf[s->EventSignalled * s->WaveRTBufSize], buf, (Length * sizeof(int16_t)));
    NtDeviceIoControlFile(s->PinHandle, s->WavePCIEvents[s->EventSignalled], NULL, NULL, &Iosb,
                          IOCTL_KS_WRITE_STREAM, NULL, 0, &s->Packet[s->EventSignalled], sizeof(KSSTREAM_HEADER));
    s->packets_used++;
    if ((s->packets_used == s->packets_total) && !s->init) {
        s->init = 1;
    }
}

static NTSTATUS GetAudioPosition(HANDLE hPin, KSAUDIO_POSITION *AudioPositionOut) {
    NTSTATUS r = STATUS_SUCCESS;
    IO_STATUS_BLOCK Iosb;
    KSPROPERTY propIn;
    propIn.Set = _KSPROPSETID_Audio;
    propIn.Id = KSPROPERTY_AUDIO_POSITION;
    propIn.Flags = KSPROPERTY_TYPE_GET;
    r = NtDeviceIoControlFile(hPin, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                              &propIn, sizeof(KSPROPERTY), AudioPositionOut, sizeof(KSAUDIO_POSITION));
    if (r == STATUS_PENDING) {
        r = NtWaitForSingleObject(hPin, FALSE, NULL);
        if (r == STATUS_SUCCESS) r = Iosb.Status;
    }
    return r;
}

void audio_wdmks_write_wavert_flt(void *wdmks, float *buf, uint32_t Length) {
    nt_wdmks_t *s = (nt_wdmks_t *)wdmks;
    int16_t *_WaveRTBuf = (int16_t*)s->WaveRTBuf;
    uint32_t _WaveRTBufSize = s->WaveRTBufSize;
    LARGE_INTEGER *_WaveRTTimeout = (s->PinNotificationSupport ? NULL : &(s->WaveRTPollTimeout));
    SIZE_T k = 0, offset;
    KSAUDIO_POSITION propOut;

    GetAudioPosition(s->PinHandle, &propOut);
    offset = (ULONG)(propOut.PlayOffset);
    offset &= (_WaveRTBufSize-1);
    while (k < Length) {
        _WaveRTBuf[((2*k + offset) & (_WaveRTBufSize-1))] = WORD2INT(buf[k]*32768.0f);
        k++;
    }
    NtWaitForSingleObject(s->EventHandle, FALSE, _WaveRTTimeout);
}

void audio_wdmks_write_wavert_s16(void *wdmks, int16_t *buf, uint32_t Length) {
    nt_wdmks_t *s = (nt_wdmks_t *)wdmks;
    int16_t *_WaveRTBuf = (int16_t*)s->WaveRTBuf;
    uint32_t _WaveRTBufSize = s->WaveRTBufSize;
    LARGE_INTEGER *_WaveRTTimeout = (s->PinNotificationSupport ? NULL : &(s->WaveRTPollTimeout));
    SIZE_T k = 0, offset;
    KSAUDIO_POSITION propOut;

    GetAudioPosition(s->PinHandle, &propOut);
    offset = (ULONG)(propOut.PlayOffset);
    offset &= (_WaveRTBufSize-1);
    while (k < Length) {
        _WaveRTBuf[((2*k + offset) & (_WaveRTBufSize-1))] = buf[k];
        k++;
    }
    NtWaitForSingleObject(s->EventHandle, FALSE, _WaveRTTimeout);
}

void audio_wdmks_close(void *wdmks) {
    nt_wdmks_t *s = (nt_wdmks_t *)wdmks;
    KSPROPERTY Property;
    KSSTATE State;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS r;

    /* Init KSPROPERTY struct (again). */
    Property.Set = _KSPROPSETID_Connection;
    Property.Id = KSPROPERTY_CONNECTION_STATE;
    Property.Flags = KSPROPERTY_TYPE_SET;

    /* Change the state to stop. */
    State = KSSTATE_STOP;
    NtDeviceIoControlFile(s->PinHandle, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                          &Property, sizeof(KSPROPERTY), &State, sizeof(State));

    /* If we got a buffer with notification support, unregister the event handle now. */
    if (s->PinNotificationSupport) {
        KSRTAUDIO_NOTIFICATION_EVENT_PROPERTY prop;
        prop.NotificationEvent = s->EventHandle;
        prop.Property.Set = _KSPROPSETID_RtAudio;
        prop.Property.Id = KSPROPERTY_RTAUDIO_UNREGISTER_NOTIFICATION_EVENT;
        prop.Property.Flags = KSPROPERTY_TYPE_GET;
        NtDeviceIoControlFile(s->PinHandle, NULL, NULL, NULL, &Iosb, IOCTL_KS_PROPERTY,
                              &prop, sizeof(KSRTAUDIO_NOTIFICATION_EVENT_PROPERTY),
                              &prop, sizeof(KSRTAUDIO_NOTIFICATION_EVENT_PROPERTY));
    }

    /* If we are a WavePCI/WaveCyclic device, free the WavePCI/WaveCyclic ringbuffer. */
    if (s->IsWavePCI) {
        NtFreeVirtualMemory(((HANDLE)-1), (void**)&(s->WaveRTBuf), 0, MEM_RELEASE);
    }

    NtClose(s->PinHandle);
    NtClose(s->FilterHandle);
    NtClose(s->EventHandle);
    NtFreeVirtualMemory(((HANDLE)-1), (void**)&s, 0, MEM_RELEASE);
}

