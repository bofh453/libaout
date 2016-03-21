#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "ntapi.h"
#include "audio_out.h"
int nt_printf(const char *fmt, ...);

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
static unsigned char n_channels = 1;

typedef WINMMAPI MMRESULT (*pWaveOutOpen)(LPHWAVEOUT phwo, UINT_PTR uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen);
typedef WINMMAPI MMRESULT (*pWaveOutClose)(HWAVEOUT hwo);
typedef WINMMAPI MMRESULT (*pWaveOutPrepareHeader)(HWAVEOUT hwo,LPWAVEHDR pwh,UINT cbwh);
typedef WINMMAPI MMRESULT (*pWaveOutUnprepareHeader)(HWAVEOUT hwo,LPWAVEHDR pwh,UINT cbwh);
typedef WINMMAPI MMRESULT (*pWaveOutWrite)(HWAVEOUT hwo,LPWAVEHDR pwh,UINT cbwh);
typedef WINMMAPI MMRESULT (*pWaveOutGetPosition)(HWAVEOUT hwo,LPMMTIME pmmt,UINT cbmmt);

typedef struct _winmm_function_dispatch_table
{
    VOID *WinMMDllHandle;
    pWaveOutOpen WaveOutOpen;
    pWaveOutClose WaveOutClose;
    pWaveOutPrepareHeader WaveOutPrepareHeader;
    pWaveOutUnprepareHeader WaveOutUnprepareHeader;
    pWaveOutWrite WaveOutWrite;
    pWaveOutGetPosition WaveOutGetPosition;
} winmm_function_dispatch_table;

static winmm_function_dispatch_table DispatchTable;

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
void audio_winmm_write_flt(void *_ao, float *data[2], unsigned int size){
    HWAVEOUT hWaveOut = (HWAVEOUT)_ao;
	WAVEHDR *current = &waveBlocks[waveCurrentBlock];
    unsigned int i, k = 0, remain;
    int16_t tmpbuf[16384];

    if (n_channels == 1) {
        for (k = 0; k < (size >> 1); k++) {
            tmpbuf[2*k] = WORD2INT(data[0][k]*32768.0f);
            tmpbuf[2*k+1] = WORD2INT(data[1][k]*32768.0f);
        }
    } else {
        for (k = 0; k < size; k++) {
            tmpbuf[k] = WORD2INT(data[0][k]*32768.0f);
        }
    }
    k = 0;

	while(size > 0) {
        int16_t *bufptr;

	    /* 
	     * first make sure the header we're going to use is unprepared
	     */
	    if(current->dwFlags & WHDR_PREPARED) 
	        DispatchTable.WaveOutUnprepareHeader(hWaveOut, current, sizeof(WAVEHDR));
	    if(size < ((BLOCK_SIZE - current->dwUser) >> 1)) {
            bufptr = (int16_t*)(current->lpData + current->dwUser);
            for (i = 0; i < size; i++) {
                bufptr[i] = tmpbuf[i+k];
            }
	        current->dwUser += (size << 1);
	        break;
	    }
	    remain = ((BLOCK_SIZE - current->dwUser) >> 1);
        bufptr = (int16_t*)(current->lpData + current->dwUser);
        for (i = 0; i < remain; i++) {
            bufptr[i] = tmpbuf[i+k];
        }
        
	    size -= remain;
        k += remain;
	    current->dwBufferLength = BLOCK_SIZE;
	    DispatchTable.WaveOutPrepareHeader(hWaveOut, current, sizeof(WAVEHDR));
	    DispatchTable.WaveOutWrite(hWaveOut, current, sizeof(WAVEHDR));
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

void audio_winmm_write_s16(void *_ao, int16_t *data[2], unsigned int size){
    HWAVEOUT hWaveOut = (HWAVEOUT)_ao;
	WAVEHDR *current = &waveBlocks[waveCurrentBlock];
    unsigned int i, k = 0, remain;
    int16_t tmpbuf[16384];

    if (n_channels == 1) {
        for (k = 0; k < (size >> 1); k++) {
            tmpbuf[2*k] = data[0][k];
            tmpbuf[2*k+1] = data[1][k];
        }
    } else {
        for (k = 0; k < size; k++) {
            tmpbuf[k] = data[0][k];
        }
    }
    k = 0;

	while(size > 0) {
        int16_t *bufptr;

	    /* 
	     * first make sure the header we're going to use is unprepared
	     */
	    if(current->dwFlags & WHDR_PREPARED) 
	        DispatchTable.WaveOutUnprepareHeader(hWaveOut, current, sizeof(WAVEHDR));
	    if(size < ((BLOCK_SIZE - current->dwUser) >> 1)) {
            bufptr = (int16_t*)(current->lpData + current->dwUser);
            for (i = 0; i < size; i++) {
                bufptr[i] = tmpbuf[i+k];
            }
	        current->dwUser += (size << 1);
	        break;
	    }
	    remain = ((BLOCK_SIZE - current->dwUser) >> 1);
        bufptr = (int16_t*)(current->lpData + current->dwUser);
        for (i = 0; i < remain; i++) {
            bufptr[i] = tmpbuf[i+k];
        }
        
	    size -= remain;
        k += remain;
	    current->dwBufferLength = BLOCK_SIZE;
	    DispatchTable.WaveOutPrepareHeader(hWaveOut, current, sizeof(WAVEHDR));
	    DispatchTable.WaveOutWrite(hWaveOut, current, sizeof(WAVEHDR));
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

static NTSTATUS AcquireWinMMImports(void) {
    UNICODE_STRING hWinMM;
    STRING ProcName;
    NTSTATUS r = STATUS_SUCCESS;
    hWinMM.Length = 18;
    hWinMM.MaximumLength = 20;
    hWinMM.Buffer = L"WinMM.dll";
    r = LdrLoadDll(NULL, NULL, &hWinMM, &DispatchTable.WinMMDllHandle);
    if (r != STATUS_SUCCESS) {
        return r;
    }
    RtlInitAnsiString(&ProcName, "waveOutOpen");
    r = LdrGetProcedureAddress(DispatchTable.WinMMDllHandle, &ProcName, 0,
                               (void**)&DispatchTable.WaveOutOpen);
    if (r != STATUS_SUCCESS) {
        nt_printf("LdrGetProcedureAddress failed for waveOutOpen: 0x%08lx\n", r);
    }
    RtlInitAnsiString(&ProcName, "waveOutClose");
    r = LdrGetProcedureAddress(DispatchTable.WinMMDllHandle, &ProcName, 0,
                               (void**)&DispatchTable.WaveOutClose);
    if (r != STATUS_SUCCESS) {
        nt_printf("LdrGetProcedureAddress failed for waveOutOpen: 0x%08lx\n", r);
    }
    RtlInitAnsiString(&ProcName, "waveOutPrepareHeader");
    r = LdrGetProcedureAddress(DispatchTable.WinMMDllHandle, &ProcName, 0,
                               (void**)&DispatchTable.WaveOutPrepareHeader);
    if (r != STATUS_SUCCESS) {
        nt_printf("LdrGetProcedureAddress failed for waveOutOpen: 0x%08lx\n", r);
    }
    RtlInitAnsiString(&ProcName, "waveOutUnprepareHeader");
    r = LdrGetProcedureAddress(DispatchTable.WinMMDllHandle, &ProcName, 0,
                               (void**)&DispatchTable.WaveOutUnprepareHeader);
    if (r != STATUS_SUCCESS) {
        nt_printf("LdrGetProcedureAddress failed for waveOutOpen: 0x%08lx\n", r);
    }
    RtlInitAnsiString(&ProcName, "waveOutWrite");
    r = LdrGetProcedureAddress(DispatchTable.WinMMDllHandle, &ProcName, 0,
                               (void**)&DispatchTable.WaveOutWrite);
    if (r != STATUS_SUCCESS) {
        nt_printf("LdrGetProcedureAddress failed for waveOutOpen: 0x%08lx\n", r);
    }
    return STATUS_SUCCESS;
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
    if (AcquireWinMMImports() != STATUS_SUCCESS) {
        return NULL;
    }
    n_channels = channels-1;
	wfx.nSamplesPerSec = sfreq;
	wfx.wBitsPerSample = 16;
	wfx.nChannels = channels; 
	wfx.cbSize = 0;
	wfx.wFormatTag = WAVE_FORMAT_PCM;
	wfx.nBlockAlign = (wfx.wBitsPerSample * wfx.nChannels) >> 3;
	wfx.nAvgBytesPerSec = wfx.nBlockAlign * wfx.nSamplesPerSec;
	r = DispatchTable.WaveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, (DWORD_PTR)waveOutProc, (DWORD_PTR)&waveFreeBlockCount, CALLBACK_FUNCTION);
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
	        DispatchTable.WaveOutUnprepareHeader(hWaveOut, &waveBlocks[i], sizeof(WAVEHDR));
    NtFreeVirtualMemory(((HANDLE)-1), (void**)&waveBlocks, 0, MEM_RELEASE); 
	DispatchTable.WaveOutClose(hWaveOut);
    LdrUnloadDll(&DispatchTable.WinMMDllHandle);
}

