#include <AudioUnit/AudioComponent.h>
#include <AudioUnit/AudioUnit.h>
#include <AudioToolbox/AudioToolbox.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/mman.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include "audio_out.h"
extern double timebase_ratio;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

typedef struct AudioFifo {
    uint8_t *buffer;
    uint8_t *rptr, *wptr, *end;
    uint32_t idx;
	uint32_t buffer_len; ///< must always be num_chunks * maxFrames
} AudioFifo;

typedef struct ao_coreaudio_s
{
  /* AudioUnit */
  AudioUnit theOutputUnit;

  /* Original common part */
  uint8_t paused;
  size_t packetSize;
  float frame_len;

  /* Ring-buffer */
  AudioFifo buf;
} ao_coreaudio_t;

/**
 * \brief add data to ringbuffer
 */
static size_t write_buffer_flt(ao_coreaudio_t *ao, float *data, size_t len){
  size_t free = ao->buf.buffer_len - ao->buf.idx;
  if (!free) {
    return 0;
  } else {
    memcpy(ao->buf.wptr, data, len * sizeof(float));
// Write memory barrier needed for SMP here in theory
    ao->buf.wptr += (len * sizeof(float));
    if (ao->buf.wptr >= ao->buf.end)
        ao->buf.wptr = ao->buf.buffer;
    ao->buf.idx += (len * sizeof(float));
    return len;
  }
}

static size_t write_buffer_s16(ao_coreaudio_t *ao, int16_t *data, size_t len){
  size_t free = ao->buf.buffer_len - ao->buf.idx;
  if (!free) {
    return 0;
  } else {
    const float scale_s16toflt = (1.0f / 32768.0f); 
    float *wptr = (float*)ao->buf.wptr;
	uint32_t i;
    for (i = 0; i < len; i++) {
        wptr[i] = ((float)data[i] * scale_s16toflt);
    }
// Write memory barrier needed for SMP here in theory
    ao->buf.wptr += (len * sizeof(float));
    if (ao->buf.wptr >= ao->buf.end)
        ao->buf.wptr = ao->buf.buffer;
    ao->buf.idx += (len * sizeof(float));
    return len;
  }
}

/**
 * \brief remove data from ringbuffer
 */
static size_t read_buffer(ao_coreaudio_t *ao, void *data, size_t len){
  size_t buffered = ao->buf.idx;
  if (len > buffered) len = buffered;
// Read memory barrier needed for SMP here in theory
  memcpy(data, ao->buf.rptr, len);
  ao->buf.rptr += len;
  if (ao->buf.rptr >= ao->buf.end)
    ao->buf.rptr -= ao->buf.end - ao->buf.buffer;
  ao->buf.idx -= len;
  return len;
}

static OSStatus theRenderProc(void *inRefCon,
                              AudioUnitRenderActionFlags *inActionFlags,
                              const AudioTimeStamp *inTimeStamp,
                              UInt32 inBusNumber, UInt32 inNumFrames,
                              AudioBufferList *ioData)
{
    ao_coreaudio_t *ao = (ao_coreaudio_t*)inRefCon;
    size_t amt=ao->buf.idx;
    size_t req=(inNumFrames)*ao->packetSize;

    if(amt>req)
        amt=req;

    if(amt) {
        read_buffer(ao, (float *)ioData->mBuffers[0].mData, amt);
    } else {
        AudioOutputUnitStop(ao->theOutputUnit);
        ao->paused = 1;
    }
    ioData->mBuffers[0].mDataByteSize = amt;
    return 0;
}

void *CoreAudioOpen(uint32_t rate, uint8_t channels, uint8_t has_sbr)
{
    AudioStreamBasicDescription inDesc;
    /* Apple has threatened to rip out the Component Manager.
     * Presumably Apple wants to completely exorcise Carbon from Darwin.
     * The structure is the same, by the way, only the name is different.
     */
    AudioComponentDescription   desc;
    AudioComponent              comp;
    AURenderCallbackStruct renderCallback;
    OSStatus err;
    UInt32 size, num_chunks, maxFrames;
    ao_coreaudio_t *ao = mempool_alloc_small(sizeof(ao_coreaudio_t), 1);

    // Build Description for the input format
    inDesc.mSampleRate=rate;
    inDesc.mFormatID=kAudioFormatLinearPCM;
    inDesc.mChannelsPerFrame=channels;
    inDesc.mBitsPerChannel=32;

    // float
    inDesc.mFormatFlags = kAudioFormatFlagIsFloat|kAudioFormatFlagIsPacked;
    // signed int
    //inDesc.mFormatFlags = kAudioFormatFlagIsSignedInteger|kAudioFormatFlagIsPacked;
    // unsigned int
    //inDesc.mFormatFlags = kAudioFormatFlagIsPacked;

    inDesc.mFramesPerPacket = 1;
    ao->packetSize = inDesc.mBytesPerPacket = inDesc.mBytesPerFrame = channels*(inDesc.mBitsPerChannel/8);
    ao->frame_len = (((has_sbr ? 2048 : 1024) * channels) / (float)rate);

    /* original analog output code */
    desc.componentType = kAudioUnitType_Output;
    desc.componentSubType = kAudioUnitSubType_DefaultOutput;
    desc.componentManufacturer = kAudioUnitManufacturer_Apple;
    desc.componentFlags = 0;
    desc.componentFlagsMask = 0;

    comp = AudioComponentFindNext(NULL, &desc);  //Finds an component that meets the desc spec's
    if (comp == NULL) {
        goto err_out;
    }

    err = AudioComponentInstanceNew(comp, &(ao->theOutputUnit));  //gains access to the services provided by the component
    if (err) {
        goto err_out;
    }

    // Initialize AudioUnit
    err = AudioUnitInitialize(ao->theOutputUnit);
    if (err) {
        goto err_out1;
    }

    size =  sizeof(AudioStreamBasicDescription);
    err = AudioUnitSetProperty(ao->theOutputUnit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Input, 0, &inDesc, size);
    if (err) {
        goto err_out2;
    }

    maxFrames = (has_sbr ? 16384 : 8192);
    size = sizeof(UInt32);
    err = AudioUnitSetProperty(ao->theOutputUnit, kAudioDevicePropertyBufferSize, kAudioUnitScope_Input, 0, &maxFrames, size);
    if (err) {
        goto err_out2;
    }
    err = AudioUnitGetProperty(ao->theOutputUnit, kAudioDevicePropertyBufferSize, kAudioUnitScope_Input, 0, &maxFrames, &size);
    if (err) {
        goto err_out2;
    }

    num_chunks = ((inDesc.mSampleRate * inDesc.mBytesPerFrame)+maxFrames-1)/maxFrames;
    ao->buf.buffer_len = num_chunks * maxFrames;
    ao->buf.buffer = mmap(NULL, ao->buf.buffer_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
    ao->buf.end = ao->buf.buffer + ao->buf.buffer_len;
    ao->buf.wptr = ao->buf.rptr = ao->buf.buffer;
    ao->buf.idx = 0;

    renderCallback.inputProc = theRenderProc;
    renderCallback.inputProcRefCon = ao;
    err = AudioUnitSetProperty(ao->theOutputUnit, kAudioUnitProperty_SetRenderCallback, kAudioUnitScope_Input, 0, &renderCallback, sizeof(AURenderCallbackStruct));
    if (err) {
        goto err_out2;
    }
    ao->paused = 1;
    return ao;

err_out2:
    AudioUnitUninitialize(ao->theOutputUnit);
err_out1:
    AudioComponentInstanceDispose(ao->theOutputUnit);
err_out:
    if(ao->buf.buffer) {
        munmap(ao->buf.buffer, ao->buf.buffer_len);
    }
    return NULL;
}

/* unload plugin and deregister from coreaudio */
void CoreAudioClose(void *_ao)
{
  ao_coreaudio_t *ao = (ao_coreaudio_t*)_ao;
  AudioOutputUnitStop(ao->theOutputUnit);
  AudioUnitUninitialize(ao->theOutputUnit);
  AudioComponentInstanceDispose(ao->theOutputUnit);

  if(ao->buf.buffer) {
    munmap(ao->buf.buffer, ao->buf.buffer_len);
  }
}

static void sleep_accurate(float delay)
{
    uint64_t deadline = delay / timebase_ratio + mach_absolute_time();
    mach_wait_until(deadline);
}

void CoreAudioWriteFlt(void *_ao, float *output_samples, uint32_t nsamples)
{
    ao_coreaudio_t *ao = (ao_coreaudio_t*)_ao;
    if(!(ao->buf.buffer_len - ao->buf.idx)) {
        sleep_accurate(ao->frame_len);
    }
    write_buffer_flt(ao, output_samples, nsamples);
    if (ao->paused) {
        /* Start callback. */
        AudioOutputUnitStart(ao->theOutputUnit);
        ao->paused = 0;
    }
}

void CoreAudioWriteS16(void *_ao, int16_t *output_samples, uint32_t nsamples)
{
    ao_coreaudio_t *ao = (ao_coreaudio_t*)_ao;
    if(!(ao->buf.buffer_len - ao->buf.idx)) {
        sleep_accurate(ao->frame_len);
    }
    write_buffer_s16(ao, output_samples, nsamples);
    if (ao->paused) {
        /* Start callback. */
        AudioOutputUnitStart(ao->theOutputUnit);
        ao->paused = 0;
    }
}

