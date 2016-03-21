#include <stdarg.h>
#include <windef.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <winbase.h>
#include <winnt.h>
#include "ntregapi.h"
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define KeyInfo(key) ((KEY_BASIC_INFORMATION*)key)
NTSTATUS NTAPI NtClose(HANDLE);
#define NT_PFX L"\\GLOBAL?"
HANDLE RtlGetConsoleHandle(void);
WINBOOL WINAPI WriteConsoleW(HANDLE hConsoleOutput,CONST VOID *lpBuffer,DWORD nNumberOfCharsToWrite,LPDWORD lpNumberOfCharsWritten,LPVOID lpReserved);

// WaveRT drivers can be found by grabbing the result from the below query under KSCATEGORY_AUDIO ({6994AD04-93EF-11D0-A3CC-00A0C9223196})
// and checking to see if it is also present under KSCATEGORY_REALTIME ({EB115FFC-10C8-4964-831D-6DCB02E6F23F}). If yes, it's a WaveRT driver.
// If no, it's a WavePCI (or god forbid, a WaveCyclic driver).
NTSTATUS NtWdmKSEnumerateAudioDevices(UNICODE_STRING *KeyName, UNICODE_STRING *AudioDevicePath, ULONG subdev_idx) 
{ 
    KEY_FULL_INFORMATION keyInfo, AudioKeyInfo; 
    NTSTATUS r;
    DWORD i, j;
    ULONG wtf;
    HANDLE hAudioKey;
    OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.ObjectName = KeyName;

    // Open the key in question.
    r = NtOpenKey(&hAudioKey, NT_KEY_READ, &oa);
    if (r != STATUS_SUCCESS) {
      return r;
    }
 
    // Get the class name and the value count. 
    r = NtQueryKey(hAudioKey, KeyFullInformation, &keyInfo, sizeof(KEY_FULL_INFORMATION), &wtf);
    if (r != STATUS_SUCCESS) {
        return r;
    }

    // Enumerate the subkeys, until RegEnumKeyEx fails.
    if (keyInfo.SubKeys) {
        for (i=0; i<keyInfo.SubKeys; i++) {
            HANDLE hSubKey, hFilterKey;
            UNICODE_STRING AudioDevKey;
            ULONG KeyInfoSizeNeeded;
            WCHAR cur_key[1000];
            SIZE_T cur_key_len = 0;
            SIZE_T sz = 0x1000;
            unsigned char *buf = NULL;
            NtAllocateVirtualMemory((HANDLE)-1, (void**)&buf, 0, &sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            r = NtEnumerateKey(hAudioKey, i, KeyBasicInformation, buf, 0x1000, &KeyInfoSizeNeeded);
            if ((r != STATUS_SUCCESS) && (KeyInfoSizeNeeded > 0x1000)) {
                return STATUS_NO_MEMORY;
            }
            memcpy(cur_key+6, KeyInfo(buf)->Name, KeyInfo(buf)->NameLength);
            memcpy(cur_key, NT_PFX, 8 * sizeof(WCHAR));
            cur_key[9] = L'\\';
            cur_key[KeyInfo(buf)->NameLength + 6] = L'\0';
            cur_key_len = KeyInfo(buf)->NameLength+6;

            memset(&oa, 0, sizeof(oa));
            oa.Length = sizeof(oa);
            oa.RootDirectory = hAudioKey;
            oa.Attributes = OBJ_CASE_INSENSITIVE;
            RtlInitUnicodeString(&AudioDevKey, KeyInfo(buf)->Name);
            oa.ObjectName = &AudioDevKey;

            r = NtOpenKey(&hSubKey, NT_KEY_READ, &oa);
            if (r != STATUS_SUCCESS) {
                NtFreeVirtualMemory(((HANDLE)-1), (void**)&buf, 0, MEM_RELEASE);
                return r;
            }

            r = NtQueryKey(hSubKey, KeyFullInformation, &AudioKeyInfo, sizeof(KEY_FULL_INFORMATION), &wtf);
            if (r != STATUS_SUCCESS) {
                continue;
            }

            for (j=0; j<AudioKeyInfo.SubKeys; j++) {
                unsigned char *strend;
                UNICODE_STRING AudioFilterKey;
                NtEnumerateKey(hSubKey, j, KeyBasicInformation, buf, 0x1000, &KeyInfoSizeNeeded);
                strend = ((unsigned char*)KeyInfo(buf)->Name + KeyInfo(buf)->NameLength);
                memcpy(strend, L"\\Control\0", 9*sizeof(WCHAR));

                oa.RootDirectory = hSubKey;
                RtlInitUnicodeString(&AudioFilterKey, KeyInfo(buf)->Name);
                oa.ObjectName = &AudioFilterKey;

                r = NtOpenKey(&hFilterKey, NT_KEY_READ, &oa);
                if (r == STATUS_SUCCESS) {
                    //wchar_t buf2[24], buf3[24];
                    unsigned char *filter_dev_strend = ((unsigned char*)KeyInfo(buf)->Name + KeyInfo(buf)->NameLength);
                    filter_dev_strend -= 16;
                    (KeyInfo(buf)->Name[0]) = L'\\';
                    //itoa16(buf2, j);
                    //itoa16(buf3, subdev_idx);
                    //nt_wdmks_printf(L"j: 0x%ls, subdev_idx: 0x%ls, subdev_name: %ls%ls\n", buf2, buf3, cur_key, KeyInfo(buf)->Name);
#ifndef TEST2
                    if ((j != subdev_idx) && (subdev_idx != 0)) {
                        continue;
                    }
                    if ((((WCHAR*)filter_dev_strend)[0] != L'T') && (((WCHAR*)filter_dev_strend)[4] != 'T')) {
                        wchar_t *tmpbuf = NULL;
                        SIZE_T tmplen = cur_key_len + KeyInfo(buf)->NameLength;
                        tmplen <<= 1;
                        NtAllocateVirtualMemory((HANDLE)-1, (void**)&tmpbuf, 0, &tmplen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
                        tmplen >>= 2;

                        // Concatenate together the full path
                        memcpy(tmpbuf, cur_key, cur_key_len+6);
                        memcpy(tmpbuf+(cur_key_len >> 1)+3, KeyInfo(buf)->Name, KeyInfo(buf)->NameLength);
                        tmpbuf[tmplen+3] = L'\0';
                        RtlInitUnicodeString(AudioDevicePath, tmpbuf);
                        NtClose(hFilterKey);
                        NtClose(hSubKey);
                        NtClose(hAudioKey);
                        NtFreeVirtualMemory(((HANDLE)-1), (void**)&buf, 0, MEM_RELEASE);
                        return STATUS_SUCCESS;
                    }
#endif
                    NtClose(hFilterKey);
                }
            }
            NtClose(hSubKey);
        }
    }
    NtClose(hAudioKey);
    return STATUS_NO_MORE_ENTRIES; 
}

#ifdef TEST
NTSTATUS NTAPI NtTerminateProcess(HANDLE,NTSTATUS);
void RtlGetCommandLine(UNICODE_STRING *wcmdln);
//#define ISSPACE(c) ((((c) == L' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))
#define ISSPACE(c) ((c) == L' ')

static ULONG atoui_w(wchar_t *str) {
    ULONG c, num = 0;
    while (*str && ISSPACE(*str)) str++;
    while (*str) {
        c = *str++ - 0x30;
        if(c > 9) break;
        num = (num << 1) + (num << 3) + c;
    }
    return num;
}

int mainCRTStartup (void)
{
  NTSTATUS r;
  HANDLE errh = RtlGetConsoleHandle();
  UNICODE_STRING AudioDevicePath, KeyName, wcmdln;
  wchar_t *argv1 = NULL;
  ULONG subdev = 0;
  DWORD done;

  RtlGetCommandLine(&wcmdln);
  argv1 = wcschr(wcmdln.Buffer, L' ');
  if (argv1 != NULL) {
    argv1++;
    subdev = atoui_w(argv1);
  }
  RtlInitUnicodeString(&KeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{6994AD04-93EF-11D0-A3CC-00A0C9223196}");
  WriteConsoleW(errh, L"Enumerating KSCATEGORY_AUDIO devices...\n", 40, &done, NULL);
  r = NtWdmKSEnumerateAudioDevices(&KeyName, &AudioDevicePath, subdev);
#ifndef TEST2
  if (r == STATUS_SUCCESS) {
    WriteConsoleW(errh, L"Device present: ", 16, &done, NULL);
    WriteConsoleW(errh, AudioDevicePath.Buffer, (AudioDevicePath.Length >> 1), &done, NULL);                        
    WriteConsoleW(errh, L"\n", 1, &done, NULL);
  } else {
    WriteConsoleW(errh, L"WTF?\n", 5, &done, NULL);
  }
#endif
  NtTerminateProcess(((HANDLE)-1), ((r == STATUS_SUCCESS) ? 0 : -1));
  return ((r == STATUS_SUCCESS) ? 0 : -1);
}
#endif

