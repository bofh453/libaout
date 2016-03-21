#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
LONG NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, VOID **BaseAddress, ULONG ZeroBits, SIZE_T *Size, ULONG Flags, ULONG Prot);
LONG NTAPI NtFreeVirtualMemory(HANDLE ProcessHandle, VOID **BaseAddress, ULONG *RegionSize, ULONG FreeType);
LONG NTAPI NtDelayExecution(BOOLEAN Alertable, LARGE_INTEGER *Interval);

/*
 * some good values for block size and count
 */
#define BLOCK_SIZE 8192
#define BLOCK_COUNT 16

/*
 * module level variables
 */
static WAVEHDR* waveBlocks;
volatile SIZE_T waveFreeBlockCount;
static int waveCurrentBlock;

#ifdef _WIN64
static void xincq(SIZE_T volatile *atomic)
{
  __asm__ __volatile__("lock; incq %0"
                       : "+m" (*atomic));
}

static int xaddq(SIZE_T volatile *atomic, LONGLONG add)
{
  LONGLONG val; /* This works for the 486 and later */
  __asm__ __volatile__("lock; xaddq %0, %1"
                       : "=r" (val), "+m" (*atomic)
                       : "m" (*atomic), "0" (add));
  return val;
}
#else
static void xincl(int volatile *atomic)
{
  __asm__ __volatile__("lock; incl %0"
                       : "+m" (*atomic));
}

static int xaddl(int volatile *atomic, int add)
{
  int val; /* This works for the 486 and later */
  __asm__ __volatile__("lock; xaddl %0, %1"
                       : "=r" (val), "+m" (*atomic)
                       : "m" (*atomic), "0" (add));
  return val;
}
#endif

void CALLBACK waveOutProc(HWAVEOUT hWaveOut, UINT uMsg, DWORD_PTR dwInstance, DWORD_PTR dwParam1, DWORD_PTR dwParam2){
	/*
	 * pointer to free block counter
	*/
	SIZE_T* freeBlockCounter = (SIZE_T*)dwInstance;

	/*
	 * ignore calls that occur due to openining and closing the
	 * device.
	 */
	if(uMsg != WOM_DONE)
	    return;
	//xaddl(freeBlockCounter, 1);
	xincq(freeBlockCounter);
}

static WAVEHDR* allocateBlocks(unsigned int size, unsigned int count){
	int i;
	WAVEHDR* blocks;
	unsigned char* buffer = NULL;
	SIZE_T totalBufferSize = (size + sizeof(WAVEHDR)) * count;

	/*
	 * allocate memory for the entire set in one go
	 */
    NtAllocateVirtualMemory(((HANDLE)-1), (void**)&buffer, 0, &totalBufferSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

	/*
	 * and set up the pointers to each bit
	 */
	blocks = (WAVEHDR*)buffer;
	buffer += sizeof(WAVEHDR) * count;
	for(i = 0; i < count; i++) {
	   blocks[i].dwBufferLength = size;
	   blocks[i].lpData = (char*)buffer;
	   buffer += size;
	}
	return blocks;
}

#define WORD2INT(x) ((x) < -32766.5f ? -32767 : ((x) > 32766.5f ? 32767 : lrintf(x)))
void audio_winmm_write_flt(void *_ao, float *data, unsigned int size){
    HWAVEOUT hWaveOut = (HWAVEOUT)_ao;
	WAVEHDR *current = &waveBlocks[waveCurrentBlock];
    unsigned int i, remain;

	while(size > 0) {
        int16_t *bufptr;

	    /* 
	     * first make sure the header we're going to use is unprepared
	     */
	    if(current->dwFlags & WHDR_PREPARED) 
	        waveOutUnprepareHeader(hWaveOut, current, sizeof(WAVEHDR));
	    if(size < ((BLOCK_SIZE - current->dwUser) >> 1)) {
            bufptr = (int16_t*)(current->lpData + current->dwUser);
            for (i = 0; i < size; i++) {
                bufptr[i] = WORD2INT(data[i]*32768.0f);
            }
	        current->dwUser += (size << 1);
	        break;
	    }
	    remain = ((BLOCK_SIZE - current->dwUser) >> 1);
        bufptr = (int16_t*)(current->lpData + current->dwUser);
        for (i = 0; i < remain; i++) {
            bufptr[i] = data[i];
        }
        
	    size -= remain;
	    data += remain;
	    current->dwBufferLength = BLOCK_SIZE;
	    waveOutPrepareHeader(hWaveOut, current, sizeof(WAVEHDR));
	    waveOutWrite(hWaveOut, current, sizeof(WAVEHDR));
	    //xaddl(&waveFreeBlockCount, -1);
	    xaddq(&waveFreeBlockCount, -1);

    	while(!waveFreeBlockCount) {
            LARGE_INTEGER TimeOut;
            TimeOut.QuadPart = -1000000;
            NtDelayExecution(FALSE, &TimeOut);
        }

	    waveCurrentBlock++;
	    waveCurrentBlock %= BLOCK_COUNT;
	    current = &waveBlocks[waveCurrentBlock];
	    current->dwUser = 0;
	}
}

void audio_winmm_write_s16(void *_ao, int16_t *data, unsigned int size){
    HWAVEOUT hWaveOut = (HWAVEOUT)_ao;
	WAVEHDR *current = &waveBlocks[waveCurrentBlock];
    unsigned int i, remain;

	while(size > 0) {
        int16_t *bufptr;

	    /* 
	     * first make sure the header we're going to use is unprepared
	     */
	    if(current->dwFlags & WHDR_PREPARED) 
	        waveOutUnprepareHeader(hWaveOut, current, sizeof(WAVEHDR));
	    if(size < ((BLOCK_SIZE - current->dwUser) >> 1)) {
            bufptr = (int16_t*)(current->lpData + current->dwUser);
            for (i = 0; i < size; i++) {
                bufptr[i] = data[i];
            }
	        current->dwUser += (size << 1);
	        break;
	    }
	    remain = ((BLOCK_SIZE - current->dwUser) >> 1);
        bufptr = (int16_t*)(current->lpData + current->dwUser);
        for (i = 0; i < remain; i++) {
            bufptr[i] = data[i];
        }
        
	    size -= remain;
	    data += remain;
	    current->dwBufferLength = BLOCK_SIZE;
	    waveOutPrepareHeader(hWaveOut, current, sizeof(WAVEHDR));
	    waveOutWrite(hWaveOut, current, sizeof(WAVEHDR));
	    //xaddl(&waveFreeBlockCount, -1);
	    xaddq(&waveFreeBlockCount, -1);

    	while(!waveFreeBlockCount) {
            LARGE_INTEGER TimeOut;
            TimeOut.QuadPart = -1000000;
            NtDelayExecution(FALSE, &TimeOut);
        }

	    waveCurrentBlock++;
	    waveCurrentBlock %= BLOCK_COUNT;
	    current = &waveBlocks[waveCurrentBlock];
	    current->dwUser = 0;
	}
}

void *audio_winmm_open(unsigned int sfreq, unsigned char channels) {
    HWAVEOUT hWaveOut;
    MMRESULT r;
	WAVEFORMATEX wfx;
	waveBlocks = allocateBlocks(BLOCK_SIZE, BLOCK_COUNT);
	waveFreeBlockCount = BLOCK_COUNT;
	waveCurrentBlock= 0;
    if(waveBlocks == NULL) {
        //*err = MMSYSERR_NOMEM;
        return NULL;
    }
	wfx.nSamplesPerSec = sfreq;
	wfx.wBitsPerSample = 16;
	wfx.nChannels = channels; 
	wfx.cbSize = 0;
	wfx.wFormatTag = WAVE_FORMAT_PCM;
	wfx.nBlockAlign = (wfx.wBitsPerSample * wfx.nChannels) >> 3;
	wfx.nAvgBytesPerSec = wfx.nBlockAlign * wfx.nSamplesPerSec;
	r = waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, (DWORD_PTR)waveOutProc, (DWORD_PTR)&waveFreeBlockCount, CALLBACK_FUNCTION);
    if (r == MMSYSERR_NOERROR) {
        return hWaveOut;
    }
    return NULL;
}

void audio_winmm_close(void *_ao) {
    HWAVEOUT hWaveOut = (HWAVEOUT)_ao;
    unsigned int i;

	while(waveFreeBlockCount < BLOCK_COUNT) {
        LARGE_INTEGER TimeOut;
        TimeOut.QuadPart = -1000000;
        NtDelayExecution(FALSE, &TimeOut);
    }

	for(i = 0; i < waveFreeBlockCount; i++) 
	    if(waveBlocks[i].dwFlags & WHDR_PREPARED)
	        waveOutUnprepareHeader(hWaveOut, &waveBlocks[i], sizeof(WAVEHDR));
    NtFreeVirtualMemory(((HANDLE)-1), (void**)&waveBlocks, 0, MEM_RELEASE); 
	waveOutClose(hWaveOut);
}

