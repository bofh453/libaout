/*++ NDK Version: 0095

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    umtypes.h

Abstract:

    Type definitions for the basic native types.

Author:

    Alex Ionescu (alex.ionescu@reactos.com)   06-Oct-2004

--*/

#if !defined(_NTAPI_) && !defined(_NTAPI_H)
#define _NTAPI_
#define _NTAPI_H

//
// NDK Applications must use Unicode
//
#ifndef UNICODE
#define UNICODE
#endif

//
// Let the NDK know we're in Application Mode
//
#define NTOS_MODE_USER

//
// Dependencies
//
#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <winnt.h>
#include <ntstatus.h>
#include <winioctl.h>

//
// Compiler Definitions
//
#ifndef _MANAGED
#if defined(_M_IX86)
#ifndef FASTCALL
#define FASTCALL                        __fastcall
#endif
#else
#define FASTCALL
#endif
#else
#define FASTCALL                        NTAPI
#endif

#if !defined(_M_CEE_PURE)
#define NTAPI_INLINE                    NTAPI
#else
#define NTAPI_INLINE
#endif

//
// Alignment Macros
//
#define ALIGN_DOWN(s, t) \
    ((ULONG)(s) & ~(sizeof(t) - 1))

#define ALIGN_UP(s, t) \
    (ALIGN_DOWN(((ULONG)(s) + sizeof(t) - 1), t))

#define ALIGN_DOWN_POINTER(p, t) \
    ((PVOID)((ULONG_PTR)(p) & ~((ULONG_PTR)sizeof(t) - 1)))

#define ALIGN_UP_POINTER(p, t) \
    (ALIGN_DOWN_POINTER(((ULONG_PTR)(p) + sizeof(t) - 1), t))

#define N_ROUND_UP(x,s) \
    (((ULONG)(x)+(s)-1) & ~((ULONG)(s)-1))

//
// Native API Return Value Macros
//
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)          ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status)              ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status)                ((((ULONG)(Status)) >> 30) == 3)

//
// Limits
//
#define MINCHAR                         0x80
#define MAXCHAR                         0x7f
#define MINSHORT                        0x8000
#define MAXSHORT                        0x7fff
#define MINLONG                         0x80000000
#define MAXLONG                         0x7fffffff
#define MAXUCHAR                        0xff
#define MAXUSHORT                       0xffff
#define MAXULONG                        0xffffffff

//
// Basic Types that aren't defined in User-Mode Headers
//
typedef CONST int CINT;
typedef CONST char *PCSZ;
typedef ULONG CLONG;
typedef short CSHORT;
typedef CSHORT *PCSHORT;
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
typedef LONG KPRIORITY;

//
// Basic NT Types
//
typedef long NTSTATUS, *PNTSTATUS;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _CSTRING
{
    USHORT Length;
    USHORT MaximumLength;
    CONST CHAR *Buffer;
} CSTRING, *PCSTRING;

typedef struct _STRING32 {
    USHORT   Length;
    USHORT   MaximumLength;
    ULONG  Buffer;
} STRING32, *PSTRING32,
  UNICODE_STRING32, *PUNICODE_STRING32,
  ANSI_STRING32, *PANSI_STRING32;

typedef struct _STRING64 {
    USHORT   Length;
    USHORT   MaximumLength;
    ULONGLONG  Buffer;
} STRING64, *PSTRING64,
  UNICODE_STRING64, *PUNICODE_STRING64,
  ANSI_STRING64, *PANSI_STRING64;

typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// Current process/thread special handle values
#define NtCurrentProcess() ((HANDLE)-1)
#define NtCurrentThread() ((HANDLE)-2)

//
// PFN Identity Uses
//
#define MMPFNUSE_PROCESSPRIVATE                             0
#define MMPFNUSE_FILE                                       1
#define MMPFNUSE_PAGEFILEMAPPED                             2
#define MMPFNUSE_PAGETABLE                                  3
#define MMPFNUSE_PAGEDPOOL                                  4
#define MMPFNUSE_NONPAGEDPOOL                               5
#define MMPFNUSE_SYSTEMPTE                                  6
#define MMPFNUSE_SESSIONPRIVATE                             7
#define MMPFNUSE_METAFILE                                   8
#define MMPFNUSE_AWEPAGE                                    9
#define MMPFNUSE_DRIVERLOCKPAGE                             10
#define MMPFNUSE_KERNELSTACK                                11

//
// Lock/Unlock Virtuam Memory Flags
//
#define MAP_PROCESS                                         1
#define MAP_SYSTEM                                          2

//
// Flags for ProcessExecutionOptions
//
#define MEM_EXECUTE_OPTION_DISABLE                          0x1
#define MEM_EXECUTE_OPTION_ENABLE                           0x2
#define MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION          0x4
#define MEM_EXECUTE_OPTION_PERMANENT                        0x8
#define MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE          0x10
#define MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE            0x20
#define MEM_EXECUTE_OPTION_VALID_FLAGS                      0x3F
#define SEC_BASED                                           0x200000

//
// Section Inherit Flags for NtCreateSection
//
typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

//
// Pool Types
//
typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,
    NonPagedPoolSession = 32,
    PagedPoolSession,
    NonPagedPoolMustSucceedSession,
    DontUseThisTypeSession,
    NonPagedPoolCacheAlignedSession,
    PagedPoolCacheAlignedSession,
    NonPagedPoolCacheAlignedMustSSession
} POOL_TYPE;

//
// Memory Manager Page Lists
//
typedef enum _MMLISTS
{
   ZeroedPageList = 0,
   FreePageList = 1,
   StandbyPageList = 2,
   ModifiedPageList = 3,
   ModifiedNoWritePageList = 4,
   BadPageList = 5,
   ActiveAndValid = 6,
   TransitionPage = 7
} MMLISTS;

//
// Per Processor Non Paged Lookaside List IDs
//
typedef enum _PP_NPAGED_LOOKASIDE_NUMBER
{
    LookasideSmallIrpList = 0,
    LookasideLargeIrpList = 1,
    LookasideMdlList = 2,
    LookasideCreateInfoList = 3,
    LookasideNameBufferList = 4,
    LookasideTwilightList = 5,
    LookasideCompletionList = 6,
    LookasideMaximumList = 7
} PP_NPAGED_LOOKASIDE_NUMBER;

//
// Memory Information Classes for NtQueryVirtualMemory
//
typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

//
// Section Information Clasess for NtQuerySection
//
typedef enum _SECTION_INFORMATION_CLASS
{
    SectionBasicInformation,
    SectionImageInformation,
} SECTION_INFORMATION_CLASS;

//
// Kinds of VADs
//
typedef enum _MI_VAD_TYPE
{
    VadNone,
    VadDevicePhysicalMemory,
    VadImageMap,
    VadAwe,
    VadWriteWatch,
    VadLargePages,
    VadRotatePhysical,
    VadLargePageSection
} MI_VAD_TYPE, *PMI_VAD_TYPE;

//
// Virtual Memory Counters
//
typedef struct _VM_COUNTERS
{
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _VM_COUNTERS_EX
{
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage;
} VM_COUNTERS_EX, *PVM_COUNTERS_EX;

//
// Sub-Information Types for PFN Identity
//
typedef struct _MEMORY_FRAME_INFORMATION
{
    ULONGLONG UseDescription:4;
    ULONGLONG ListDescription:3; ULONGLONG Reserved0:1; ULONGLONG Pinned:1; ULONGLONG DontUse:48; ULONGLONG Priority:3; ULONGLONG Reserved:4;
} MEMORY_FRAME_INFORMATION, *PMEMORY_FRAME_INFORMATION;

typedef struct _FILEOFFSET_INFORMATION
{
    ULONGLONG DontUse:9;
    ULONGLONG Offset:48; ULONGLONG Reserved:7;
} FILEOFFSET_INFORMATION, *PFILEOFFSET_INFORMATION;

typedef struct _PAGEDIR_INFORMATION
{
    ULONGLONG DontUse:9;
    ULONGLONG PageDirectoryBase:48; ULONGLONG Reserved:7;
} PAGEDIR_INFORMATION, *PPAGEDIR_INFORMATION;

typedef struct _UNIQUE_PROCESS_INFORMATION
{
    ULONGLONG DontUse:9;
    ULONGLONG UniqueProcessKey:48; ULONGLONG Reserved:7;
} UNIQUE_PROCESS_INFORMATION, *PUNIQUE_PROCESS_INFORMATION;

//
// PFN Identity Data Structure
//
typedef struct _MMPFN_IDENTITY
{
    union
    {
        MEMORY_FRAME_INFORMATION e1;
        FILEOFFSET_INFORMATION e2;
        PAGEDIR_INFORMATION e3;
        UNIQUE_PROCESS_INFORMATION e4;
    } u1;
    SIZE_T PageFrameIndex;
    union
    {
        struct
        {
            ULONG Image:1;
            ULONG Mismatch:1;
        } e1;
        PVOID FileObject;
        PVOID UniqueFileObjectKey;
        PVOID ProtoPteAddress;
        PVOID VirtualAddress;
    } u2;
} MMPFN_IDENTITY, *PMMPFN_IDENTITY;

//
// List of Working Sets
//
typedef struct _MEMORY_WORKING_SET_LIST
{
    ULONG NumberOfPages;
    ULONG WorkingSetList[1];
} MEMORY_WORKING_SET_LIST, *PMEMORY_WORKING_SET_LIST;

//
// Memory Information Structures for NtQueryVirtualMemory
//
typedef struct
{
    UNICODE_STRING SectionFileName;
    WCHAR NameBuffer[ANYSIZE_ARRAY];
} MEMORY_SECTION_NAME, *PMEMORY_SECTION_NAME;

//
// Section Information Structures for NtQuerySection
//
typedef struct _SECTION_BASIC_INFORMATION
{ PVOID           BaseAddress;
    ULONG           Attributes; LARGE_INTEGER   Size;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION
{
    PVOID EntryPoint;
    ULONG ZeroBits;
    SIZE_T StackReserved;
    SIZE_T StackCommit;
    ULONG SubSystemType;
    union
    {
        struct
        {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    UCHAR ImageContainsCode;
    UCHAR Spare1;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG Reserved[1];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

//
// Well Known SIDs
//
#define SECURITY_INTERNETSITE_AUTHORITY     {0,0,0,0,0,7}

//
// Privilege constants
//
#define SE_MIN_WELL_KNOWN_PRIVILEGE       (2L)
#define SE_CREATE_TOKEN_PRIVILEGE         (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE   (3L)
#define SE_LOCK_MEMORY_PRIVILEGE          (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE       (5L)
#define SE_UNSOLICITED_INPUT_PRIVILEGE    (6L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE      (6L)
#define SE_TCB_PRIVILEGE                  (7L)
#define SE_SECURITY_PRIVILEGE             (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE       (9L)
#define SE_LOAD_DRIVER_PRIVILEGE          (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE       (11L)
#define SE_SYSTEMTIME_PRIVILEGE           (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE  (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE    (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE      (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE     (16L)
#define SE_BACKUP_PRIVILEGE               (17L)
#define SE_RESTORE_PRIVILEGE              (18L)
#define SE_SHUTDOWN_PRIVILEGE             (19L)
#define SE_DEBUG_PRIVILEGE                (20L)
#define SE_AUDIT_PRIVILEGE                (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE   (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE        (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE      (24L)
#define SE_UNDOCK_PRIVILEGE               (25L)
#define SE_SYNC_AGENT_PRIVILEGE           (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE    (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE        (28L)
#define SE_IMPERSONATE_PRIVILEGE          (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE        (30L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE       (SE_CREATE_GLOBAL_PRIVILEGE)

typedef struct _TOKEN_MANDATORY_POLICY {
  ULONG Policy;
} TOKEN_MANDATORY_POLICY, *PTOKEN_MANDATORY_POLICY;

typedef struct _TOKEN_ACCESS_INFORMATION
{
    struct _SID_AND_ATTRIBUTES_HASH *SidHash;
    struct _SID_AND_ATTRIBUTES_HASH *RestrictedSidHash;
    struct _TOKEN_PRIVILEGES *Privileges;
    LUID AuthenticationId;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    TOKEN_MANDATORY_POLICY MandatoryPolicy;
    ULONG Flags;
} TOKEN_ACCESS_INFORMATION, *PTOKEN_ACCESS_INFORMATION;

//
// Definitions for Object Creation
//
#define OBJ_INHERIT                             0x00000002L
#define OBJ_PERMANENT                           0x00000010L
#define OBJ_EXCLUSIVE                           0x00000020L
#define OBJ_CASE_INSENSITIVE                    0x00000040L
#define OBJ_OPENIF                              0x00000080L
#define OBJ_OPENLINK                            0x00000100L
#define OBJ_KERNEL_HANDLE                       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK                  0x00000400L
#define OBJ_VALID_ATTRIBUTES                    0x000007F2L

#define InitializeObjectAttributes(p,n,a,r,s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = (r); \
    (p)->Attributes = (a); \
    (p)->ObjectName = (n); \
    (p)->SecurityDescriptor = (s); \
    (p)->SecurityQualityOfService = NULL; \
}

//
// Number of custom-defined bits that can be attached to a handle
//
#define OBJ_HANDLE_TAGBITS                      0x3

//
// Directory Object Access Rights
//
#define DIRECTORY_QUERY                         0x0001
#define DIRECTORY_TRAVERSE                      0x0002
#define DIRECTORY_CREATE_OBJECT                 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY           0x0008
#define DIRECTORY_ALL_ACCESS                    (STANDARD_RIGHTS_REQUIRED | 0xF)

//
// Slash separator used in the OB Namespace (and Registry)
//
#define OBJ_NAME_PATH_SEPARATOR                 L'\\'

//
// Object Duplication Flags
//
#define DUPLICATE_SAME_ATTRIBUTES               0x00000004

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//
// Object Information Types for NtQueryInformationObject
//
typedef struct _OBJECT_BASIC_INFORMATION
{
    ULONG Attributes;
    ACCESS_MASK GrantedAccess; ULONG HandleCount; ULONG PointerCount; ULONG PagedPoolUsage; ULONG NonPagedPoolUsage; ULONG Reserved[3]; ULONG NameInformationLength; ULONG TypeInformationLength; ULONG SecurityDescriptorLength; LARGE_INTEGER CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects; ULONG TotalNumberOfHandles; ULONG TotalPagedPoolUsage; ULONG TotalNonPagedPoolUsage; ULONG TotalNamePoolUsage; ULONG TotalHandleTableUsage; ULONG HighWaterNumberOfObjects; ULONG HighWaterNumberOfHandles; ULONG HighWaterPagedPoolUsage; ULONG HighWaterNonPagedPoolUsage; ULONG HighWaterNamePoolUsage; ULONG HighWaterHandleTableUsage; ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask; BOOLEAN SecurityRequired; BOOLEAN MaintainHandleCount; ULONG PoolType; ULONG DefaultPagedPoolCharge; ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_HANDLE_ATTRIBUTE_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_ATTRIBUTE_INFORMATION, *POBJECT_HANDLE_ATTRIBUTE_INFORMATION;

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef struct _OBJECT_ALL_TYPES_INFORMATION
{
    ULONG NumberOfTypes;
    //OBJECT_TYPE_INFORMATION TypeInformation[1];
} OBJECT_ALL_TYPES_INFORMATION, *POBJECT_ALL_TYPES_INFORMATION;

//
// Object Information Classes for NtQueryInformationObject
//
typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

//
// Event Object Access Masks
//
#define EVENT_QUERY_STATE                   0x0001

//
// Semaphore Object Access Masks
//
#define SEMAPHORE_QUERY_STATE               0x0001

//
// Event Pair Access Masks
//
#define EVENT_PAIR_ALL_ACCESS               0x1F0000L

//
// Profile Object Access Masks
//
#define PROFILE_CONTROL                     0x0001
#define PROFILE_ALL_ACCESS                  (STANDARD_RIGHTS_REQUIRED | PROFILE_CONTROL)

//
// NtRaiseHardError-related parameters
//
#define MAXIMUM_HARDERROR_PARAMETERS        4
#define HARDERROR_OVERRIDE_ERRORMODE        0x10000000

//
// Pushlock bits
//
#define EX_PUSH_LOCK_LOCK_V                 ((ULONG_PTR)0x0)
#define EX_PUSH_LOCK_LOCK                   ((ULONG_PTR)0x1)
#define EX_PUSH_LOCK_WAITING                ((ULONG_PTR)0x2)
#define EX_PUSH_LOCK_WAKING                 ((ULONG_PTR)0x4)
#define EX_PUSH_LOCK_MULTIPLE_SHARED        ((ULONG_PTR)0x8)
#define EX_PUSH_LOCK_SHARE_INC              ((ULONG_PTR)0x10)
#define EX_PUSH_LOCK_PTR_BITS               ((ULONG_PTR)0xf)

//
// Pushlock Wait Block Flags
//
#define EX_PUSH_LOCK_FLAGS_EXCLUSIVE        1
#define EX_PUSH_LOCK_FLAGS_WAIT_V           1
#define EX_PUSH_LOCK_FLAGS_WAIT             2

//
// Don't include WMI headers just for one define
//
#ifndef PEVENT_TRACE_HEADER_DEFINED
#define PEVENT_TRACE_HEADER_DEFINED
typedef struct _EVENT_TRACE_HEADER *PEVENT_TRACE_HEADER;
#endif

//
// Event Types
//
typedef enum _EVENT_TYPE
{
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

//
// Timer Types
//
typedef enum _TIMER_TYPE
{
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE;

//
// Wait Types
//
typedef enum _WAIT_TYPE
{
    WaitAll,
    WaitAny
} WAIT_TYPE;

//
// Thread States
//
typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
#if (NTDDI_VERSION >= NTDDI_WS03)
    GateWait
#endif
} KTHREAD_STATE, *PKTHREAD_STATE;

//
// Kernel Object Types
//
typedef enum _KOBJECTS
{
    EventNotificationObject = 0,
    EventSynchronizationObject = 1,
    MutantObject = 2,
    ProcessObject = 3,
    QueueObject = 4,
    SemaphoreObject = 5,
    ThreadObject = 6,
    GateObject = 7,
    TimerNotificationObject = 8,
    TimerSynchronizationObject = 9,
    Spare2Object = 10,
    Spare3Object = 11,
    Spare4Object = 12,
    Spare5Object = 13,
    Spare6Object = 14,
    Spare7Object = 15,
    Spare8Object = 16,
    Spare9Object = 17,
    ApcObject = 18,
    DpcObject = 19,
    DeviceQueueObject = 20,
    EventPairObject = 21,
    InterruptObject = 22,
    ProfileObject = 23,
    ThreadedDpcObject = 24,
    MaximumKernelObject = 25
} KOBJECTS;

//
// Timer Routine
//
typedef VOID
(NTAPI *PTIMER_APC_ROUTINE)(PVOID TimerContext, ULONG TimerLowValue, LONG TimerHighValue);

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,
    NEC98x86,
    EndAlternatives,
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
    UINT  TickCountLow;
    UINT  TickCountMultiplier;
    KSYSTEM_TIME  InterruptTime;
    KSYSTEM_TIME  SystemTime;
    KSYSTEM_TIME  TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR WindowsDirectory[MAX_PATH];
    UINT MaxStackTraceDepth;
    UINT CryptoExponent;
    UINT TimeZoneId;
    UINT Reserved2[8];
    UINT NtProductType;
    BOOLEAN ProductIsValid;
    UINT NtMajorVersion;
    UINT NtMinorVersion;
    BOOLEAN ProcessorFeatures[64];
    UINT Reserved1;
    UINT Reserved3;
    UINT TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    LARGE_INTEGER SystemExpirationDate;
    UINT SuiteMask;
    BOOLEAN KdDebuggerEnabled; BOOLEAN NXSupportPolicy;
    UINT ActiveConsoleId;
    UINT DismountCount;
    UINT ComPlusPackage;
    UINT LastSystemRITEventTickCount;
    UINT NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    UINT TraceLogging;
    ULONGLONG TestRetInstruction; ULONGLONG SystemCall[4];
} KUSER_SHARED_DATA;

//
// I/O Completion Access Rights
//
#define IO_COMPLETION_QUERY_STATE               0x0001

//
// Symbolic Link Access Rights
//
#define SYMBOLIC_LINK_QUERY                     0x0001
#define SYMBOLIC_LINK_ALL_ACCESS                STANDARD_RIGHTS_REQUIRED | 0x0001

//
// NtCreateFile Result Flags
//
#define FILE_SUPERSEDED                         0x00000000
#define FILE_OPENED                             0x00000001
#define FILE_CREATED                            0x00000002
#define FILE_OVERWRITTEN                        0x00000003
#define FILE_EXISTS                             0x00000004
#define FILE_DOES_NOT_EXIST                     0x00000005

//
// Pipe Flags
//
#define FILE_PIPE_BYTE_STREAM_TYPE              0x00000000
#define FILE_PIPE_MESSAGE_TYPE                  0x00000001
#define FILE_PIPE_BYTE_STREAM_MODE              0x00000000
#define FILE_PIPE_MESSAGE_MODE                  0x00000001
#define FILE_PIPE_QUEUE_OPERATION               0x00000000
#define FILE_PIPE_COMPLETE_OPERATION            0x00000001
#define FILE_PIPE_INBOUND                       0x00000000
#define FILE_PIPE_OUTBOUND                      0x00000001
#define FILE_PIPE_FULL_DUPLEX                   0x00000002
#define FILE_PIPE_CLIENT_END                    0x00000000
#define FILE_PIPE_SERVER_END                    0x00000001

//
// NtCreateFile Attributes
//
#define FILE_ATTRIBUTE_VALID_FLAGS              0x00007fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS          0x000031a7

//
// NtCreateFile OpenType Flags
//
#define FILE_SUPERSEDE                          0x00000000
#define FILE_OPEN                               0x00000001
#define FILE_CREATE                             0x00000002
#define FILE_OPEN_IF                            0x00000003
#define FILE_OVERWRITE                          0x00000004
#define FILE_OVERWRITE_IF                       0x00000005
#define FILE_MAXIMUM_DISPOSITION                0x00000005

//
// NtCreateFile Flags
//
#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080
#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800
#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000
#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000
#define FILE_SHARE_ALL FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

//
// Device Charactertics
//
#define FILE_REMOVABLE_MEDIA                    0x00000001
#define FILE_READ_ONLY_DEVICE                   0x00000002
#define FILE_FLOPPY_DISKETTE                    0x00000004
#define FILE_WRITE_ONCE_MEDIA                   0x00000008
#define FILE_REMOTE_DEVICE                      0x00000010
#define FILE_DEVICE_IS_MOUNTED                  0x00000020
#define FILE_VIRTUAL_VOLUME                     0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME          0x00000080
#define FILE_DEVICE_SECURE_OPEN                 0x00000100

//
// File Object Flags
//
#define FO_FILE_OBJECT_HAS_EXTENSION            0x00800000

//
// Device Object Extension Flags
//
#define DOE_UNLOAD_PENDING                      0x1
#define DOE_DELETE_PENDING                      0x2
#define DOE_REMOVE_PENDING                      0x4
#define DOE_REMOVE_PROCESSED                    0x8
#define DOE_START_PENDING                       0x10

//
// Device Object StartIo Flags
//
#define DOE_SIO_NO_KEY                          0x20
#define DOE_SIO_WITH_KEY                        0x40
#define DOE_SIO_CANCELABLE                      0x80
#define DOE_SIO_DEFERRED                        0x100
#define DOE_SIO_NO_CANCEL                       0x200

//
// Device Node Flags
//
#define DNF_PROCESSED                           0x00000001
#define DNF_STARTED                             0x00000002
#define DNF_START_FAILED                        0x00000004
#define DNF_ENUMERATED                          0x00000008
#define DNF_DELETED                             0x00000010
#define DNF_MADEUP                              0x00000020
#define DNF_START_REQUEST_PENDING               0x00000040
#define DNF_NO_RESOURCE_REQUIRED                0x00000080
#define DNF_INSUFFICIENT_RESOURCES              0x00000100
#define DNF_RESOURCE_ASSIGNED                   0x00000200
#define DNF_RESOURCE_REPORTED                   0x00000400
#define DNF_HAL_NODE                            0x00000800 // ???
#define DNF_ADDED                               0x00001000
#define DNF_ADD_FAILED                          0x00002000
#define DNF_LEGACY_DRIVER                       0x00004000
#define DNF_STOPPED                             0x00008000
#define DNF_WILL_BE_REMOVED                     0x00010000
#define DNF_NEED_TO_ENUM                        0x00020000
#define DNF_NOT_CONFIGURED                      0x00040000
#define DNF_REINSTALL                           0x00080000
#define DNF_RESOURCE_REQUIREMENTS_NEED_FILTERED 0x00100000 // ???
#define DNF_DISABLED                            0x00200000
#define DNF_RESTART_OK                          0x00400000
#define DNF_NEED_RESTART                        0x00800000
#define DNF_VISITED                             0x01000000
#define DNF_ASSIGNING_RESOURCES                 0x02000000
#define DNF_BEEING_ENUMERATED                   0x04000000
#define DNF_NEED_ENUMERATION_ONLY               0x08000000
#define DNF_LOCKED                              0x10000000
#define DNF_HAS_BOOT_CONFIG                     0x20000000
#define DNF_BOOT_CONFIG_RESERVED                0x40000000
#define DNF_HAS_PROBLEM                         0x80000000 // ???

//
// Device Node User Flags
//
#define DNUF_DONT_SHOW_IN_UI                    0x0002
#define DNUF_NOT_DISABLEABLE                    0x0008

//
// Internal Option Flags
//
#define IO_ATTACH_DEVICE_API                    0x80000000

//
// Undocumented WMI Registration Flags
//
#define WMIREG_FLAG_TRACE_PROVIDER              0x00010000
#define WMIREG_FLAG_TRACE_NOTIFY_MASK           0x00F00000
#define WMIREG_NOTIFY_DISK_IO                   0x00100000
#define WMIREG_NOTIFY_TDI_IO                    0x00200000

#define MAX_BUS_NAME 24

//
// PLUGPLAY_CONTROL_RELATED_DEVICE_DATA.Relations
//
#define PNP_GET_PARENT_DEVICE           1
#define PNP_GET_CHILD_DEVICE            2
#define PNP_GET_SIBLING_DEVICE          3

//
// PLUGPLAY_CONTROL_STATUS_DATA Operations
//
#define PNP_GET_DEVICE_STATUS           0
#define PNP_SET_DEVICE_STATUS           1
#define PNP_CLEAR_DEVICE_STATUS         2

//
// I/O Completion Information Class for NtQueryIoCompletionInformation
//
typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
    IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

//
//  System Information Classes for NtQueryAtom
//
typedef enum _ATOM_INFORMATION_CLASS
{
    AtomBasicInformation,
    AtomTableInformation,
} ATOM_INFORMATION_CLASS;

//
//  System Information Classes for NtQueryEvent
//
typedef enum _EVENT_INFORMATION_CLASS
{
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

//
// Hardware Interface Type
//
typedef enum _INTERFACE_TYPE
{
    InterfaceTypeUndefined = -1,
    Internal,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    VMEBus,
    NuBus,
    PCMCIABus,
    CBus,
    MPIBus,
    MPSABus,
    ProcessorInternal,
    InternalPowerBus,
    PNPISABus,
    PNPBus,
    MaximumInterfaceType
}INTERFACE_TYPE, *PINTERFACE_TYPE;

typedef enum _BUS_DATA_TYPE
{
    ConfigurationSpaceUndefined = -1,
    Cmos,
    EisaConfiguration,
    Pos,
    CbusConfiguration,
    PCIConfiguration,
    VMEConfiguration,
    NuBusConfiguration,
    PCMCIAConfiguration,
    MPIConfiguration,
    MPSAConfiguration,
    PNPISAConfiguration,
    SgiInternalConfiguration,
    MaximumBusDataType
} BUS_DATA_TYPE, *PBUS_DATA_TYPE;

//
// File Information Classes for NtQueryInformationFile
//
typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

//
// File Information Classes for NtQueryInformationFileSystem
//
typedef enum _FSINFOCLASS
{
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

//
// Dock Profile Status
//
typedef enum _PROFILE_STATUS
{
    DOCK_NOTDOCKDEVICE,
    DOCK_QUIESCENT,
    DOCK_ARRIVING,
    DOCK_DEPARTING,
    DOCK_EJECTIRP_COMPLETED
} PROFILE_STATUS, *PPROFILE_STATUS;

//
// Device Node States
//
typedef enum _PNP_DEVNODE_STATE
{
    DeviceNodeUnspecified = 0x300,
    DeviceNodeUninitialized = 0x301,
    DeviceNodeInitialized = 0x302,
    DeviceNodeDriversAdded = 0x303,
    DeviceNodeResourcesAssigned = 0x304,
    DeviceNodeStartPending = 0x305,
    DeviceNodeStartCompletion = 0x306,
    DeviceNodeStartPostWork = 0x307,
    DeviceNodeStarted = 0x308,
    DeviceNodeQueryStopped = 0x309,
    DeviceNodeStopped = 0x30a,
    DeviceNodeRestartCompletion = 0x30b,
    DeviceNodeEnumeratePending = 0x30c,
    DeviceNodeEnumerateCompletion = 0x30d,
    DeviceNodeAwaitingQueuedDeletion = 0x30e,
    DeviceNodeAwaitingQueuedRemoval = 0x30f,
    DeviceNodeQueryRemoved = 0x310,
    DeviceNodeRemovePendingCloses = 0x311,
    DeviceNodeRemoved = 0x312,
    DeviceNodeDeletePendingCloses = 0x313,
    DeviceNodeDeleted = 0x314,
    MaxDeviceNodeState = 0x315,
} PNP_DEVNODE_STATE;

//
// Pipe Structures for IOCTL_PIPE_XXX
//
typedef struct _FILE_PIPE_WAIT_FOR_BUFFER
{ LARGE_INTEGER Timeout;
    ULONG NameLength; BOOLEAN TimeoutSpecified;
    WCHAR Name[1];
} FILE_PIPE_WAIT_FOR_BUFFER, *PFILE_PIPE_WAIT_FOR_BUFFER;

typedef struct _FILE_PIPE_PEEK_BUFFER
{
    ULONG NamedPipeState;
    ULONG ReadDataAvailable; ULONG NumberOfMessages; ULONG MessageLength;
    CHAR Data[1];
} FILE_PIPE_PEEK_BUFFER, *PFILE_PIPE_PEEK_BUFFER;

//
// I/O Error Log Structures
//
typedef struct _IO_ERROR_LOG_PACKET
{
    UCHAR MajorFunctionCode;
    UCHAR RetryCount;
    USHORT DumpDataSize;
    USHORT NumberOfStrings;
    USHORT StringOffset;
    USHORT EventCategory;
    NTSTATUS ErrorCode;
    ULONG UniqueErrorValue;
    NTSTATUS FinalStatus;
    ULONG SequenceNumber;
    ULONG IoControlCode;
    LARGE_INTEGER DeviceOffset;
    ULONG DumpData[1];
}IO_ERROR_LOG_PACKET, *PIO_ERROR_LOG_PACKET;

typedef struct _IO_ERROR_LOG_MESSAGE
{
    USHORT Type;
    USHORT Size;
    USHORT DriverNameLength;
    LARGE_INTEGER TimeStamp;
    ULONG DriverNameOffset;
    IO_ERROR_LOG_PACKET EntryData;
} IO_ERROR_LOG_MESSAGE, *PIO_ERROR_LOG_MESSAGE;

//
// I/O Completion Information structures
//
typedef struct _IO_COMPLETION_BASIC_INFORMATION
{ LONG Depth;
} IO_COMPLETION_BASIC_INFORMATION, *PIO_COMPLETION_BASIC_INFORMATION;

//
// Parameters for NtCreateMailslotFile/NtCreateNamedPipeFile
//
typedef struct _MAILSLOT_CREATE_PARAMETERS
{
    ULONG MailslotQuota;
    ULONG MaximumMessageSize; LARGE_INTEGER ReadTimeout; BOOLEAN TimeoutSpecified;
} MAILSLOT_CREATE_PARAMETERS, *PMAILSLOT_CREATE_PARAMETERS;

typedef struct _NAMED_PIPE_CREATE_PARAMETERS
{
    ULONG NamedPipeType;
    ULONG ReadMode; ULONG CompletionMode; ULONG MaximumInstances; ULONG InboundQuota; ULONG OutboundQuota; LARGE_INTEGER DefaultTimeout; BOOLEAN TimeoutSpecified;
} NAMED_PIPE_CREATE_PARAMETERS, *PNAMED_PIPE_CREATE_PARAMETERS;

//
// Firmware Boot File Path
//
typedef struct _FILE_PATH
{
    ULONG Version;
    ULONG Length; ULONG Type;
    CHAR FilePath[1];
} FILE_PATH, *PFILE_PATH;

//
// Firmware Boot Options
//
typedef struct _BOOT_OPTIONS
{
    ULONG Version;
    ULONG Length; ULONG Timeout; ULONG CurrentBootEntryId; ULONG NextBootEntryId;
    WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

//
// Firmware Boot Entry
//
typedef struct _BOOT_ENTRY
{
    ULONG Version;
    ULONG Length; ULONG Id; ULONG Attributes; ULONG FriendlyNameOffset; ULONG BootFilePathOffset; ULONG OsOptionsLength;
    CHAR OsOptions[1];
} BOOT_ENTRY, *PBOOT_ENTRY;

//
// Firmware Driver Entry
//
typedef struct _EFI_DRIVER_ENTRY
{
    ULONG Version;
    ULONG Length; ULONG Id; ULONG Attributes; ULONG FriendlyNameOffset; ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

//
// APC Callback for NtCreateFile
//
typedef VOID
(NTAPI *PIO_APC_ROUTINE)(PVOID ApcContext, IO_STATUS_BLOCK *IoStatusBlock, ULONG Reserved);

//
// Plag and Play Classes
//
typedef enum _PLUGPLAY_CONTROL_CLASS
{
    PlugPlayControlUserResponse = 0x07,
    PlugPlayControlProperty = 0x0A,
    PlugPlayControlGetRelatedDevice = 0x0C,
    PlugPlayControlDeviceStatus = 0x0E,
    PlugPlayControlGetDeviceDepth,
    PlugPlayControlResetDevice = 0x14
} PLUGPLAY_CONTROL_CLASS;

typedef enum _PLUGPLAY_BUS_CLASS
{
    SystemBus,
    PlugPlayVirtualBus,
    MaxPlugPlayBusClass
} PLUGPLAY_BUS_CLASS, *PPLUGPLAY_BUS_CLASS;

//
// Plag and Play Bus Types
//
typedef enum _PLUGPLAY_VIRTUAL_BUS_TYPE
{
    Root,
    MaxPlugPlayVirtualBusType
} PLUGPLAY_VIRTUAL_BUS_TYPE, *PPLUGPLAY_VIRTUAL_BUS_TYPE;

//
// Plag and Play Event Categories
//
typedef enum _PLUGPLAY_EVENT_CATEGORY
{
    HardwareProfileChangeEvent,
    TargetDeviceChangeEvent,
    DeviceClassChangeEvent,
    CustomDeviceEvent,
    DeviceInstallEvent,
    DeviceArrivalEvent,
    PowerEvent,
    VetoEvent,
    BlockedDriverEvent,
    MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY;

//
// Plug and Play Event Block
//
typedef struct _PLUGPLAY_EVENT_BLOCK
{
    GUID EventGuid;
    PLUGPLAY_EVENT_CATEGORY EventCategory;
    PULONG Result;
    ULONG Flags;
    ULONG TotalSize;
    PVOID DeviceObject;
    union
    {
        struct
        {
            GUID ClassGuid;
            WCHAR SymbolicLinkName[ANYSIZE_ARRAY];
        } DeviceClass;
        struct
        {
            WCHAR DeviceIds[ANYSIZE_ARRAY];
        } TargetDevice;
        struct
        {
            WCHAR DeviceId[ANYSIZE_ARRAY];
        } InstallDevice;
        struct
        {
            PVOID NotificationStructure;
            WCHAR DeviceIds[ANYSIZE_ARRAY];
        } CustomNotification;
        struct
        {
            PVOID Notification;
        } ProfileNotification;
        struct
        {
            ULONG NotificationCode;
            ULONG NotificationData;
        } PowerNotification;
        struct
        {
            INT VetoType;
            WCHAR DeviceIdVetoNameBuffer[ANYSIZE_ARRAY];
        } VetoNotification;
        struct
        {
            GUID BlockedDriverGuid;
        } BlockedDriverNotification;
    };
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

//
// Plug and Play Control Classes
//

//Class 0x0A
typedef struct _PLUGPLAY_CONTROL_PROPERTY_DATA
{
    UNICODE_STRING DeviceInstance;
    ULONG Property;
    PVOID Buffer;
    ULONG BufferSize;
} PLUGPLAY_CONTROL_PROPERTY_DATA, *PPLUGPLAY_CONTROL_PROPERTY_DATA;

// Class 0x0C
typedef struct _PLUGPLAY_CONTROL_RELATED_DEVICE_DATA
{
    UNICODE_STRING TargetDeviceInstance;
    ULONG Relation;
    PWCHAR RelatedDeviceInstance;
    ULONG RelatedDeviceInstanceLength;
} PLUGPLAY_CONTROL_RELATED_DEVICE_DATA, *PPLUGPLAY_CONTROL_RELATED_DEVICE_DATA;

// Class 0x0E
typedef struct _PLUGPLAY_CONTOL_STATUS_DATA
{
    UNICODE_STRING DeviceInstance;
    ULONG Operation;
    ULONG DeviceStatus;
    ULONG DeviceProblem;
} PLUGPLAY_CONTROL_STATUS_DATA, *PPLUGPLAY_CONTROL_STATUS_DATA;

// Class 0x0F
typedef struct _PLUGPLAY_CONTROL_DEPTH_DATA
{
    UNICODE_STRING DeviceInstance;
    ULONG Depth;
} PLUGPLAY_CONTROL_DEPTH_DATA, *PPLUGPLAY_CONTROL_DEPTH_DATA;

// Class 0x14
typedef struct _PLUGPLAY_CONTROL_RESET_DEVICE_DATA
{
   UNICODE_STRING DeviceInstance;
} PLUGPLAY_CONTROL_RESET_DEVICE_DATA, *PPLUGPLAY_CONTROL_RESET_DEVICE_DATA;

//
// Plug and Play Bus Type Definition
//
typedef struct _PLUGPLAY_BUS_TYPE
{
    PLUGPLAY_BUS_CLASS BusClass;
    union
    {
        INTERFACE_TYPE SystemBusType;
        PLUGPLAY_VIRTUAL_BUS_TYPE PlugPlayVirtualBusType;
    };
} PLUGPLAY_BUS_TYPE, *PPLUGPLAY_BUS_TYPE;

//
// Plug and Play Bus Instance Definition
//
typedef struct _PLUGPLAY_BUS_INSTANCE
{
    PLUGPLAY_BUS_TYPE BusType;
    ULONG BusNumber;
    WCHAR BusName[MAX_BUS_NAME];
} PLUGPLAY_BUS_INSTANCE, *PPLUGPLAY_BUS_INSTANCE;

//
//  System Information Classes for NtQuerySystemInformation
//
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation, /// Obsolete: Use KUSER_SHARED_DATA
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInformationNative,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation,
    SystemLoadGdiDriverInSystemSpaceInformation,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHanfleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchDogTimerHandler,
    SystemWatchDogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformationObsolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPathInformation,
    SystemVerifierFaultsInformation,
    MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS;

//
// Information Structures for NtQuerySystemInformation
//
typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

// Class 1
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT Reserved;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

// Class 2
typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG Spare3Count;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

// Class 3
typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
#if (NTDDI_VERSION >= NTDDI_WIN2K)
     ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
#endif
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

// Class 4
// This class is obsolete, please use KUSER_SHARED_DATA instead

// Class 5
typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
    ULONG PadPadAlignment;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
#ifndef _WIN64
C_ASSERT(sizeof(SYSTEM_THREAD_INFORMATION) == 0x40);
    // Must be 8-byte aligned
#endif

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize; //VISTA ULONG HardFaultCount; //WIN7 ULONG NumberOfThreadsHighWatermark; //WIN7 ULONGLONG CycleTime; //WIN7 LARGE_INTEGER CreateTime; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount; ULONG SessionId; ULONG_PTR PageDirectoryBase;

    //
    // This part corresponds to VM_COUNTERS_EX.
    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
    //
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;

    //
    // This part corresponds to IO_COUNTERS
    // LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
//    SYSTEM_THREAD_INFORMATION TH[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
#ifndef _WIN64
C_ASSERT(sizeof(SYSTEM_PROCESS_INFORMATION) == 0xB8);
    // Must be 8-byte aligned
#endif

//
// Class 6
typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
    ULONG Length;
    ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

// Class 7
typedef struct _SYSTEM_DEVICE_INFORMATION
{
    ULONG NumberOfDisks;
    ULONG NumberOfFloppies;
    ULONG NumberOfCdRoms;
    ULONG NumberOfTapes;
    ULONG NumberOfSerialPorts;
    ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

// Class 8
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

// Class 9
typedef struct _SYSTEM_FLAGS_INFORMATION
{
    ULONG Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

// Class 10
typedef struct _SYSTEM_CALL_TIME_INFORMATION
{
    ULONG Length;
    ULONG TotalCalls;
    LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION;

// Class 11 - See RTL_PROCESS_MODULES

// Class 12 - See RTL_PROCESS_LOCKS

// Class 13 - See RTL_PROCESS_BACKTRACES

// Class 14 - 15
typedef struct _SYSTEM_POOL_ENTRY
{
    BOOLEAN Allocated;
    BOOLEAN Spare0;
    USHORT AllocatorBackTraceIndex;
    ULONG Size;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
        PVOID ProcessChargedQuota;
    };
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION
{
    SIZE_T TotalSize;
    PVOID FirstEntry;
    USHORT EntryOverhead;
    BOOLEAN PoolTagPresent; BOOLEAN Spare0; ULONG NumberOfEntries;
    SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

// Class 16
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object; ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// Class 17
typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfObjects;
    ULONG NumberOfHandles;
    ULONG TypeIndex;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG PoolType;
    BOOLEAN SecurityRequired;
    BOOLEAN WaitableObject;
    UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION
{
    ULONG NextEntryOffset;
    PVOID Object;
    HANDLE CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Flags;
    LONG PointerCount;
    LONG HandleCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    HANDLE ExclusiveProcessId; PVOID SecurityDescriptor;
    OBJECT_NAME_INFORMATION NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

// Class 18
typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG TotalInUse;
    ULONG PeakUsage;
    UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

// Class 19
typedef struct _SYSTEM_VDM_INSTEMUL_INFO
{
    ULONG SegmentNotPresent;
    ULONG VdmOpcode0F;
    ULONG OpcodeESPrefix;
    ULONG OpcodeCSPrefix;
    ULONG OpcodeSSPrefix;
    ULONG OpcodeDSPrefix;
    ULONG OpcodeFSPrefix;
    ULONG OpcodeGSPrefix;
    ULONG OpcodeOPER32Prefix;
    ULONG OpcodeADDR32Prefix;
    ULONG OpcodeINSB;
    ULONG OpcodeINSW;
    ULONG OpcodeOUTSB;
    ULONG OpcodeOUTSW;
    ULONG OpcodePUSHF;
    ULONG OpcodePOPF;
    ULONG OpcodeINTnn;
    ULONG OpcodeINTO;
    ULONG OpcodeIRET;
    ULONG OpcodeINBimm;
    ULONG OpcodeINWimm;
    ULONG OpcodeOUTBimm;
    ULONG OpcodeOUTWimm ;
    ULONG OpcodeINB;
    ULONG OpcodeINW;
    ULONG OpcodeOUTB;
    ULONG OpcodeOUTW;
    ULONG OpcodeLOCKPrefix;
    ULONG OpcodeREPNEPrefix;
    ULONG OpcodeREPPrefix;
    ULONG OpcodeHLT;
    ULONG OpcodeCLI;
    ULONG OpcodeSTI;
    ULONG BopCount;
} SYSTEM_VDM_INSTEMUL_INFO, *PSYSTEM_VDM_INSTEMUL_INFO;

// Class 20 - ULONG VDMBOPINFO

// Class 21
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount; ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

// Class 22
typedef struct _SYSTEM_POOLTAG
{
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
    ULONG PagedAllocs; ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs; ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

// Class 23
typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

// Class 24
typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
    ULONG Spare;
    ULONG DpcQueueDepth;
    ULONG MinimumDpcRate;
    ULONG AdjustDpcThreshold;
    ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

// Class 25
typedef struct _SYSTEM_MEMORY_INFO
{
    PUCHAR StringOffset;
    USHORT ValidCount;
    USHORT TransitionCount;
    USHORT ModifiedCount;
    USHORT PageTableCount;
} SYSTEM_MEMORY_INFO, *PSYSTEM_MEMORY_INFO;

typedef struct _SYSTEM_MEMORY_INFORMATION
{
    ULONG InfoSize;
    ULONG StringStart;
    SYSTEM_MEMORY_INFO Memory[1];
} SYSTEM_MEMORY_INFORMATION, *PSYSTEM_MEMORY_INFORMATION;

// Class 26
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
    ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION;

// Class 27
// Not an actually class, simply a PVOID to the ImageAddress

// Class 28
typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    ULONG TimeIncrement;
    BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

// Class 29 - Same as 25

// FIXME: Class 30

// Class 31
typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
   UCHAR TraceEnable;
   UCHAR TracePermanent;
   UNICODE_STRING TraceProcessName;
   UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION;

// Class 32 - OBSOLETE

// Class 33
typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
    ULONG AlignmentFixupCount;
    ULONG ExceptionDispatchCount;
    ULONG FloatingEmulationCount;
    ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

// Class 34
typedef struct _SYSTEM_CRASH_STATE_INFORMATION
{
    ULONG ValidCrashDump;
} SYSTEM_CRASH_STATE_INFORMATION, *PSYSTEM_CRASH_STATE_INFORMATION;

// Class 35
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

// Class 36
typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
    ULONG ContextSwitches;
    ULONG FindAny;
    ULONG FindLast;
    ULONG FindIdeal;
    ULONG IdleAny;
    ULONG IdleCurrent;
    ULONG IdleLast;
    ULONG IdleIdeal;
    ULONG PreemptAny;
    ULONG PreemptCurrent;
    ULONG PreemptLast;
    ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

// Class 37
typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
    ULONG RegistryQuotaAllowed;
    ULONG RegistryQuotaUsed;
    SIZE_T PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

// Class 38
// Not a structure, simply send the UNICODE_STRING

// Class 39
// Not a structure, simply send a ULONG containing the new separation

// Class 40
typedef struct _SYSTEM_PLUGPLAY_BUS_INFORMATION
{
    ULONG BusCount;
    PLUGPLAY_BUS_INSTANCE BusInstance[1];
} SYSTEM_PLUGPLAY_BUS_INFORMATION, *PSYSTEM_PLUGPLAY_BUS_INFORMATION;

// Class 41
typedef enum _SYSTEM_DOCK_STATE
{
    SystemDockStateUnknown,
    SystemUndocked,
    SystemDocked
} SYSTEM_DOCK_STATE, *PSYSTEM_DOCK_STATE;

typedef struct _SYSTEM_DOCK_INFORMATION
{
    SYSTEM_DOCK_STATE DockState;
    INTERFACE_TYPE DeviceBusType;
    ULONG DeviceBusNumber;
    ULONG SlotNumber;
} SYSTEM_DOCK_INFORMATION, *PSYSTEM_DOCK_INFORMATION;

// Class 42
typedef struct _SYSTEM_POWER_INFORMATION_NATIVE
{
    BOOLEAN SystemSuspendSupported;
    BOOLEAN SystemHibernateSupported;
    BOOLEAN ResumeTimerSupportsSuspend;
    BOOLEAN ResumeTimerSupportsHibernate;
    BOOLEAN LidSupported;
    BOOLEAN TurboSettingSupported;
    BOOLEAN TurboMode;
    BOOLEAN SystemAcOrDc;
    BOOLEAN PowerDownDisabled;
    LARGE_INTEGER SpindownDrives;
} SYSTEM_POWER_INFORMATION_NATIVE, *PSYSTEM_POWER_INFORMATION_NATIVE;

// Class 43
typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
{
    INT VetoType;
    UNICODE_STRING VetoDriver;
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

// Class 44
//typedef struct _TIME_ZONE_INFORMATION RTL_TIME_ZONE_INFORMATION;

// Class 45
typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
    USHORT CurrentDepth;
    USHORT MaximumDepth;
    ULONG TotalAllocates;
    ULONG AllocateMisses;
    ULONG TotalFrees;
    ULONG FreeMisses;
    ULONG Type;
    ULONG Tag;
    ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

// Class 46
// Not a structure. Only a HANDLE for the SlipEvent;

// Class 47
// Not a structure. Only a ULONG for the SessionId;

// Class 48
// Not a structure. Only a ULONG for the SessionId;

// FIXME: Class 49

// Class 50
// Not a structure. Only a ULONG_PTR for the SystemRangeStart

// Class 51
typedef struct _SYSTEM_VERIFIER_INFORMATION
{
   ULONG NextEntryOffset;
   ULONG Level;
   UNICODE_STRING DriverName;
   ULONG RaiseIrqls;
   ULONG AcquireSpinLocks;
   ULONG SynchronizeExecutions;
   ULONG AllocationsAttempted;
   ULONG AllocationsSucceeded;
   ULONG AllocationsSucceededSpecialPool;
   ULONG AllocationsWithNoTag;
   ULONG TrimRequests;
   ULONG Trims;
   ULONG AllocationsFailed;
   ULONG AllocationsFailedDeliberately;
   ULONG Loads;
   ULONG Unloads;
   ULONG UnTrackedPool;
   ULONG CurrentPagedPoolAllocations;
   ULONG CurrentNonPagedPoolAllocations;
   ULONG PeakPagedPoolAllocations;
   ULONG PeakNonPagedPoolAllocations;
   SIZE_T PagedPoolUsageInBytes;
   SIZE_T NonPagedPoolUsageInBytes;
   SIZE_T PeakPagedPoolUsageInBytes;
   SIZE_T PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION;

// FIXME: Class 52

// Class 53
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer;
    // Same format as in SystemProcessInformation
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

// FIXME: Class 54-97

//
// Hotpatch flags
//
#define RTL_HOTPATCH_SUPPORTED_FLAG         0x01
#define RTL_HOTPATCH_SWAP_OBJECT_NAMES      0x08 << 24
#define RTL_HOTPATCH_SYNC_RENAME_FILES      0x10 << 24
#define RTL_HOTPATCH_PATCH_USER_MODE        0x20 << 24
#define RTL_HOTPATCH_REMAP_SYSTEM_DLL       0x40 << 24
#define RTL_HOTPATCH_PATCH_KERNEL_MODE      0x80 << 24


// Class 69
typedef struct _SYSTEM_HOTPATCH_CODE_INFORMATION
{
    ULONG Flags;
    ULONG InfoSize;
    union
    {
        struct
        {
            ULONG Foo;
        } CodeInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
        } KernelInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
            USHORT TargetNameOffset;
            USHORT TargetNameLength;
            UCHAR PatchingFinished;
        } UserModeInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
            USHORT TargetNameOffset;
            USHORT TargetNameLength;
            UCHAR PatchingFinished;
            NTSTATUS ReturnCode;
            HANDLE TargetProcess;
        } InjectionInfo;
        struct
        {
            HANDLE FileHandle1;
            PIO_STATUS_BLOCK IoStatusBlock1;
            PVOID RenameInformation1;
            PVOID RenameInformationLength1;
            HANDLE FileHandle2;
            PIO_STATUS_BLOCK IoStatusBlock2;
            PVOID RenameInformation2;
            PVOID RenameInformationLength2;
        } RenameInfo;
        struct
        {
            HANDLE ParentDirectory;
            HANDLE ObjectHandle1;
            HANDLE ObjectHandle2;
        } AtomicSwap;
    };
} SYSTEM_HOTPATCH_CODE_INFORMATION, *PSYSTEM_HOTPATCH_CODE_INFORMATION;

//
// Class 75
//
#if 0
typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
{
    ULONG ProviderSignature;
    BOOLEAN Register;
    PFNFTH FirmwareTableHandler;
    PVOID DriverObject;
} SYSTEM_FIRMWARE_TABLE_HANDLER, *PSYSTEM_FIRMWARE_TABLE_HANDLER;
#endif

//
// Class 76
//
#if 0
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    ULONG ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID; ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;
#endif

//
// Class 81
//
typedef struct _SYSTEM_MEMORY_LIST_INFORMATION
{
   SIZE_T ZeroPageCount;
   SIZE_T FreePageCount;
   SIZE_T ModifiedPageCount;
   SIZE_T ModifiedNoWritePageCount;
   SIZE_T BadPageCount;
   SIZE_T PageCountByPriority[8];
   SIZE_T RepurposedPagesByPriority[8];
   SIZE_T ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION, *PSYSTEM_MEMORY_LIST_INFORMATION;

//
// File Information structures for NtQueryInformationFile
//
typedef struct _FILE_BASIC_INFORMATION
{ LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION
{ LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_STREAM_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG StreamNameLength;
    LARGE_INTEGER StreamSize;
    LARGE_INTEGER StreamAllocationSize;
    WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{ LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_EA_INFORMATION
{
    ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_COMPRESSION_INFORMATION
{ LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION
{
  LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION
{
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_FULL_EA_INFORMATION
{
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_QUOTA_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG SidLength;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER QuotaUsed;
    LARGE_INTEGER QuotaThreshold;
    LARGE_INTEGER QuotaLimit;
    SID Sid;
} FILE_QUOTA_INFORMATION, *PFILE_QUOTA_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION
{ LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION
{
    BOOLEAN ReplaceIfExists;
    HANDLE  RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_PIPE_INFORMATION
{
    ULONG ReadMode;
    ULONG CompletionMode;
} FILE_PIPE_INFORMATION, *PFILE_PIPE_INFORMATION;

typedef struct _FILE_PIPE_LOCAL_INFORMATION
{
    ULONG NamedPipeType;
    ULONG NamedPipeConfiguration;
    ULONG MaximumInstances;
    ULONG CurrentInstances;
    ULONG InboundQuota;
    ULONG ReadDataAvailable;
    ULONG OutboundQuota;
    ULONG WriteQuotaAvailable;
    ULONG NamedPipeState;
    ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;

typedef struct _FILE_PIPE_REMOTE_INFORMATION
{ LARGE_INTEGER CollectDataTime;
    ULONG MaximumCollectionCount;
} FILE_PIPE_REMOTE_INFORMATION, *PFILE_PIPE_REMOTE_INFORMATION;

typedef struct _FILE_MAILSLOT_QUERY_INFORMATION
{
    ULONG MaximumMessageSize;
    ULONG MailslotQuota;
    ULONG NextMessageSize;
    ULONG MessagesAvailable;
    LARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_QUERY_INFORMATION, *PFILE_MAILSLOT_QUERY_INFORMATION;

typedef struct _FILE_MAILSLOT_SET_INFORMATION
{ PLARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_SET_INFORMATION, *PFILE_MAILSLOT_SET_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION
{
    HANDLE Port;
    PVOID Key;
} FILE_COMPLETION_INFORMATION, *PFILE_COMPLETION_INFORMATION;

typedef struct _FILE_LINK_INFORMATION
{
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

typedef struct _FILE_NAME_INFORMATION
{
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_ALLOCATION_INFORMATION
{ LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION
{ LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION
{ LARGE_INTEGER ValidDataLength;
} FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{ PVOID KeyContext;
    PVOID ApcContext;
    IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION
{
    ULONG FileAttributes;
    ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;

//
// File System Information structures for NtQueryInformationFile
//
typedef struct _FILE_FS_DEVICE_INFORMATION
{
    DEVICE_TYPE DeviceType;
    ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION
{
    ULONG FileSystemAttributes;
    ULONG MaximumComponentNameLength;
    ULONG FileSystemNameLength;
    WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

typedef struct _FILE_FS_SIZE_INFORMATION
{ LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;

typedef struct _FILE_FS_FULL_SIZE_INFORMATION
{ LARGE_INTEGER   TotalAllocationUnits;
    LARGE_INTEGER   CallerAvailableAllocationUnits;
    LARGE_INTEGER   ActualAvailableAllocationUnits;
    ULONG           SectorsPerAllocationUnit;
    ULONG           BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION, *PFILE_FS_FULL_SIZE_INFORMATION;

typedef struct _FILE_FS_LABEL_INFORMATION
{
    ULONG VolumeLabelLength;
    WCHAR VolumeLabel[1];
} FILE_FS_LABEL_INFORMATION, *PFILE_FS_LABEL_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION
{ LARGE_INTEGER VolumeCreationTime;
    ULONG VolumeSerialNumber;
    ULONG VolumeLabelLength;
    BOOLEAN SupportsObjects;
    WCHAR VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

//
// Port Object Access Masks
//
#define PORT_CONNECT                    0x1
#define PORT_ALL_ACCESS                 (STANDARD_RIGHTS_REQUIRED | \
                                         SYNCHRONIZE | \
                                         PORT_CONNECT)

//
// Port Object Flags
//
#define LPCP_CONNECTION_PORT            0x00000001
#define LPCP_UNCONNECTED_PORT           0x00000002
#define LPCP_COMMUNICATION_PORT         0x00000003
#define LPCP_CLIENT_PORT                0x00000004
#define LPCP_PORT_TYPE_MASK             0x0000000F
#define LPCP_PORT_DELETED               0x10000000
#define LPCP_WAITABLE_PORT              0x20000000
#define LPCP_NAME_DELETED               0x40000000
#define LPCP_SECURITY_DYNAMIC           0x80000000

//
// Maximum message size that can be sent through an LPC Port without a section
//
#ifdef _WIN64
#define PORT_MAXIMUM_MESSAGE_LENGTH 512
#else
#define PORT_MAXIMUM_MESSAGE_LENGTH 256
#endif

//
// LPC Message Types
//
typedef enum _LPC_TYPE
{
    LPC_NEW_MESSAGE,
    LPC_REQUEST,
    LPC_REPLY,
    LPC_DATAGRAM,
    LPC_LOST_REPLY,
    LPC_PORT_CLOSED,
    LPC_CLIENT_DIED,
    LPC_EXCEPTION,
    LPC_DEBUG_EVENT,
    LPC_ERROR_EVENT,
    LPC_CONNECTION_REQUEST,
    LPC_CONNECTION_REFUSED,
    LPC_MAXIMUM
} LPC_TYPE;

//
// Information Classes for NtQueryInformationPort
//
typedef enum _PORT_INFORMATION_CLASS
{
    PortNoInformation
} PORT_INFORMATION_CLASS;

//
// Portable LPC Types for 32/64-bit compatibility
//
#ifdef USE_LPC6432
#define LPC_CLIENT_ID CLIENT_ID64
#define LPC_SIZE_T ULONGLONG
#define LPC_PVOID ULONGLONG
#define LPC_HANDLE ULONGLONG
#else
#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE
#endif

//
// LPC Port Message
//
typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        LPC_CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        LPC_SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

//
// Local and Remove Port Views
//
typedef struct _PORT_VIEW
{
    ULONG Length;
    LPC_HANDLE SectionHandle;
    ULONG SectionOffset;
    LPC_SIZE_T ViewSize;
    LPC_PVOID ViewBase;
    LPC_PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW
{
    ULONG Length;
    LPC_SIZE_T ViewSize;
    LPC_PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

//
// LPC Kernel-Mode Message Structures defined for size only
//
typedef struct _LPCP_MESSAGE
{
    UCHAR Data[0x14];
    PORT_MESSAGE Request;
} LPCP_MESSAGE;

typedef struct _LPCP_CONNECTION_MESSAGE
{
    UCHAR Data[0x2C];
} LPCP_CONNECTION_MESSAGE;

//
// Hard Error LPC Message
//
typedef struct _HARDERROR_MSG
{
    PORT_MESSAGE h;
    NTSTATUS Status;
    LARGE_INTEGER ErrorTime;
    ULONG ValidResponseOptions;
    ULONG Response;
    ULONG NumberOfParameters;
    ULONG UnicodeStringParameterMask;
    ULONG_PTR Parameters[MAXIMUM_HARDERROR_PARAMETERS];
} HARDERROR_MSG, *PHARDERROR_MSG;

//
// Client Died LPC Message
//
typedef struct _CLIENT_DIED_MSG
{
    PORT_MESSAGE h;
    LARGE_INTEGER CreateTime;
} CLIENT_DIED_MSG, *PCLIENT_DIED_MSG;

//
// Maximum total Kernel-Mode LPC Message Structure Size
//
#define LPCP_MAX_MESSAGE_SIZE \
    N_ROUND_UP(PORT_MAXIMUM_MESSAGE_LENGTH + \
    sizeof(LPCP_MESSAGE) + \
    sizeof(LPCP_CONNECTION_MESSAGE), 16)

//
// Maximum actual LPC Message Length
//
#define LPC_MAX_MESSAGE_LENGTH \
    (LPCP_MAX_MESSAGE_SIZE - \
    FIELD_OFFSET(LPCP_MESSAGE, Request))

//
// Maximum actual size of LPC Message Data
//
#define LPC_MAX_DATA_LENGTH \
    (LPC_MAX_MESSAGE_LENGTH - \
    sizeof(PORT_MESSAGE) - \
    sizeof(LPCP_CONNECTION_MESSAGE))

//
// Debug Object Access Masks
//
#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)

//
// Debug Event Flags
//
#define DEBUG_EVENT_READ                  (0x01)
#define DEBUG_EVENT_NOWAIT                (0x02)
#define DEBUG_EVENT_INACTIVE              (0x04)
#define DEBUG_EVENT_RELEASE               (0x08)
#define DEBUG_EVENT_PROTECT_FAILED        (0x10)
#define DEBUG_EVENT_SUSPEND               (0x20)

//
// NtCreateDebugObject Flags
//
#define DBGK_KILL_PROCESS_ON_EXIT         (0x1)
#define DBGK_ALL_FLAGS                    (DBGK_KILL_PROCESS_ON_EXIT)

//
// Debug Object Information Classes for NtQueryDebugObject
//
typedef enum _DEBUGOBJECTINFOCLASS
{
    DebugObjectUnusedInformation,
    DebugObjectKillProcessOnExitInformation
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

//
// Debug Message API Number
//
typedef enum _DBGKM_APINUMBER
{
    DbgKmExceptionApi = 0,
    DbgKmCreateThreadApi = 1,
    DbgKmCreateProcessApi = 2,
    DbgKmExitThreadApi = 3,
    DbgKmExitProcessApi = 4,
    DbgKmLoadDllApi = 5,
    DbgKmUnloadDllApi = 6,
    DbgKmErrorReportApi = 7,
    DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;

//
// Debug States
//
typedef enum _DBG_STATE
{
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

//
// Debug Object Information Structures
//
typedef struct _DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION
{
    ULONG KillProcessOnExit;
} DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION, *PDEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION;

//
// Debug Message Structures
//
typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{ PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

//
// User-Mode Debug State Change Structure
//
typedef struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union
    {
        struct
        {
            HANDLE HandleToThread;
            DBGKM_CREATE_THREAD NewThread;
        } CreateThread;
        struct
        {
            HANDLE HandleToProcess;
            HANDLE HandleToThread;
            DBGKM_CREATE_PROCESS NewProcess;
        } CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_EXCEPTION Exception;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

//
// Shutdown types for NtShutdownSystem
//
typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

//
// Responses for NtRaiseHardError
//
typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem,
    OptionOkNoWait,
    OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes,
    ResponseTryAgain,
    ResponseContinue
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

//
// LPC Debug Message
//
typedef struct _DBGKM_MSG
{
    PORT_MESSAGE h;
    DBGKM_APINUMBER ApiNumber;
    NTSTATUS ReturnedStatus;
    union
    {
        DBGKM_EXCEPTION Exception;
        DBGKM_CREATE_THREAD CreateThread;
        DBGKM_CREATE_PROCESS CreateProcess;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    };
} DBGKM_MSG, *PDBGKM_MSG;

//
// Debug Control Codes for NtSystemDebugcontrol
//
typedef enum _SYSDBG_COMMAND
{
    SysDbgQueryModuleInformation = 0,
    SysDbgQueryTraceInformation = 1,
    SysDbgSetTracepoint = 2,
    SysDbgSetSpecialCall = 3,
    SysDbgClearSpecialCalls = 4,
    SysDbgQuerySpecialCalls = 5,
    SysDbgBreakPoint = 6,
    SysDbgQueryVersion = 7,
    SysDbgReadVirtual = 8,
    SysDbgWriteVirtual = 9,
    SysDbgReadPhysical = 10,
    SysDbgWritePhysical = 11,
    SysDbgReadControlSpace = 12,
    SysDbgWriteControlSpace = 13,
    SysDbgReadIoSpace = 14,
    SysDbgWriteIoSpace = 15,
    SysDbgReadMsr = 16,
    SysDbgWriteMsr = 17,
    SysDbgReadBusData = 18,
    SysDbgWriteBusData = 19,
    SysDbgCheckLowMemory = 20,
    SysDbgEnableKernelDebugger = 21,
    SysDbgDisableKernelDebugger = 22,
    SysDbgGetAutoKdEnable = 23,
    SysDbgSetAutoKdEnable = 24,
    SysDbgGetPrintBufferSize = 25,
    SysDbgSetPrintBufferSize = 26,
    SysDbgGetKdUmExceptionEnable = 27,
    SysDbgSetKdUmExceptionEnable = 28,
    SysDbgGetTriageDump = 29,
    SysDbgGetKdBlockEnable = 30,
    SysDbgSetKdBlockEnable = 31,
    SysDbgRegisterForUmBreakInfo = 32,
    SysDbgGetUmBreakPid = 33,
    SysDbgClearUmBreakPid = 34,
    SysDbgGetUmAttachPid = 35,
    SysDbgClearUmAttachPid = 36,
} SYSDBG_COMMAND;

//
// System Debugger Types
//
typedef struct _SYSDBG_PHYSICAL
{
    PHYSICAL_ADDRESS Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_PHYSICAL, *PSYSDBG_PHYSICAL;

typedef struct _SYSDBG_VIRTUAL
{
    PVOID Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

typedef struct _SYSDBG_CONTROL_SPACE
{
    ULONGLONG Address;
    PVOID Buffer;
    ULONG Request;
    ULONG Processor;
} SYSDBG_CONTROL_SPACE, *PSYSDBG_CONTROL_SPACE;

typedef struct _SYSDBG_IO_SPACE
{
    ULONGLONG Address;
    PVOID Buffer;
    ULONG Request;
    INTERFACE_TYPE InterfaceType;
    ULONG BusNumber;
    ULONG AddressSpace;
} SYSDBG_IO_SPACE, *PSYSDBG_IO_SPACE;

typedef struct _SYSDBG_BUS_DATA
{
    ULONG Address;
    PVOID Buffer;
    ULONG Request;
    BUS_DATA_TYPE BusDataType;
    ULONG BusNumber;
    ULONG SlotNumber;
} SYSDBG_BUS_DATA, *PSYSDBG_BUS_DATA;

typedef struct _SYSDBG_MSR
{
    ULONG Address;
    ULONGLONG Data;
} SYSDBG_MSR, *PSYSDBG_MSR;

typedef struct _SYSDBG_TRIAGE_DUMP
{
    ULONG Flags;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    ULONG ProcessHandles;
    ULONG ThreadHandles;
    PHANDLE Handles;
} SYSDBG_TRIAGE_DUMP, *PSYSDBG_TRIAGE_DUMP;

//
// KD Structures
//
typedef struct _KD_SYMBOLS_INFO
{
    PVOID BaseOfDll;
    ULONG_PTR ProcessId;
    ULONG CheckSum;
    ULONG SizeOfImage;
} KD_SYMBOLS_INFO, *PKD_SYMBOLS_INFO;

//
// Loader Data Table Entry Flags
//
#define LDRP_STATIC_LINK                        0x00000002
#define LDRP_IMAGE_DLL                          0x00000004
#define LDRP_LOAD_IN_PROGRESS                   0x00001000
#define LDRP_UNLOAD_IN_PROGRESS                 0x00002000
#define LDRP_ENTRY_PROCESSED                    0x00004000
#define LDRP_ENTRY_INSERTED                     0x00008000
#define LDRP_CURRENT_LOAD                       0x00010000
#define LDRP_FAILED_BUILTIN_LOAD                0x00020000
#define LDRP_DONT_CALL_FOR_THREADS              0x00040000
#define LDRP_PROCESS_ATTACH_CALLED              0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED               0x00100000
#define LDRP_IMAGE_NOT_AT_BASE                  0x00200000
#define LDRP_COR_IMAGE                          0x00400000
#define LDR_COR_OWNS_UNMAP                      0x00800000
#define LDRP_SYSTEM_MAPPED                      0x01000000
#define LDRP_IMAGE_VERIFYING                    0x02000000
#define LDRP_DRIVER_DEPENDENT_DLL               0x04000000
#define LDRP_ENTRY_NATIVE                       0x08000000
#define LDRP_REDIRECTED                         0x10000000
#define LDRP_NON_PAGED_DEBUG_INFO               0x20000000
#define LDRP_MM_LOADED                          0x40000000
#define LDRP_COMPAT_DATABASE_PROCESSED          0x80000000

//
// Dll Characteristics for LdrLoadDll
//
#define LDR_IGNORE_CODE_AUTHZ_LEVEL                 0x00001000

//
// LdrAddRef Flags
//
#define LDR_ADDREF_DLL_PIN                          0x00000001

//
// LdrLockLoaderLock Flags
//
#define LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS   0x00000001
#define LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY          0x00000002

//
// LdrUnlockLoaderLock Flags
//
#define LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001

//
// LdrGetDllHandleEx Flags
//
#define LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT    0x00000001
#define LDR_GET_DLL_HANDLE_EX_PIN                   0x00000002


#define LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID           0
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED     1
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED 2

//
// FIXME: THIS SHOULD *NOT* BE USED!
//
#define IMAGE_SCN_TYPE_NOLOAD                   0x00000002

//
// Loader datafile/imagemapping macros
//
#define LDR_IS_DATAFILE(handle)     (((ULONG_PTR)(handle)) & (ULONG_PTR)1)
#define LDR_IS_IMAGEMAPPING(handle) (((ULONG_PTR)(handle)) & (ULONG_PTR)2)
#define LDR_IS_RESOURCE(handle)     (LDR_IS_IMAGEMAPPING(handle) || LDR_IS_DATAFILE(handle))

//
// Resource Type Levels
//
#define RESOURCE_TYPE_LEVEL                     0
#define RESOURCE_NAME_LEVEL                     1
#define RESOURCE_LANGUAGE_LEVEL                 2
#define RESOURCE_DATA_LEVEL                     3

//
// Loader Data stored in the PEB
//
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized; PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
#if (NTDDI_VERSION >= NTDDI_WIN7)
    UCHAR ShutdownInProgress;
    PVOID ShutdownThreadId;
#endif
} PEB_LDR_DATA, *PPEB_LDR_DATA;

//
// Loader Data Table Entry
//
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//
// Loaded Imports Reference Counting in Kernel
//
typedef struct _LOAD_IMPORTS
{
    SIZE_T Count;
    PLDR_DATA_TABLE_ENTRY Entry[1];
} LOAD_IMPORTS, *PLOAD_IMPORTS;

//
// Loader Resource Information
//
typedef struct _LDR_RESOURCE_INFO
{
    ULONG_PTR Type;
    ULONG_PTR Name;
    ULONG_PTR Language;
} LDR_RESOURCE_INFO, *PLDR_RESOURCE_INFO;

typedef struct _LDR_ENUM_RESOURCE_INFO
{
    ULONG_PTR Type;
    ULONG_PTR Name;
    ULONG_PTR Language;
    PVOID Data;
    SIZE_T Size;
    ULONG_PTR Reserved;
} LDR_ENUM_RESOURCE_INFO, *PLDR_ENUM_RESOURCE_INFO;

//
// DLL Notifications
//
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
    ULONG Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef VOID
(NTAPI *PLDR_DLL_LOADED_NOTIFICATION_CALLBACK)(BOOLEAN Type,
struct _LDR_DLL_LOADED_NOTIFICATION_DATA *Data);

typedef struct _LDR_DLL_LOADED_NOTIFICATION_ENTRY
{
    LIST_ENTRY NotificationListEntry;
    PLDR_DLL_LOADED_NOTIFICATION_CALLBACK Callback;
} LDR_DLL_LOADED_NOTIFICATION_ENTRY, *PLDR_DLL_LOADED_NOTIFICATION_ENTRY;

//
// Alternate Resources Support
//
typedef struct _ALT_RESOURCE_MODULE
{
    LANGID LangId;
    PVOID ModuleBase;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID ModuleManifest;
#endif
    PVOID AlternateModule;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    HANDLE AlternateFileHandle;
    ULONG ModuleCheckSum;
    ULONG ErrorCode;
#endif
} ALT_RESOURCE_MODULE, *PALT_RESOURCE_MODULE;

//
// Callback function for LdrEnumerateLoadedModules
//
typedef VOID (NTAPI LDR_ENUM_CALLBACK)(IN PLDR_DATA_TABLE_ENTRY ModuleInformation, PVOID Parameter, BOOLEAN *Stop);
typedef LDR_ENUM_CALLBACK *PLDR_ENUM_CALLBACK;

//
// DLL Main Routine
//
typedef BOOLEAN
(NTAPI *PDLL_INIT_ROUTINE)(PVOID DllHandle, ULONG Reason, PCONTEXT Context);

//
// ASSERT Macros
//
#if DBG

#define ASSERT( exp ) \
    ((void)((!(exp)) ? \
        (RtlAssert( (PVOID)#exp, (PVOID)__FILE__, __LINE__, NULL ),FALSE) : \
        TRUE))

#define ASSERTMSG( msg, exp ) \
    ((void)((!(exp)) ? \
        (RtlAssert( (PVOID)#exp, (PVOID)__FILE__, __LINE__, (PCHAR)msg ),FALSE) : \
        TRUE))

#else

#define ASSERT( exp )         ((void) 0)
#define ASSERTMSG( msg, exp ) ((void) 0)

#endif

//
// Maximum Atom Length
//
#define RTL_MAXIMUM_ATOM_LENGTH                             255

//
// Process Parameters Flags
//
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_USER            0x02
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL          0x04
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER          0x08
#define RTL_USER_PROCESS_PARAMETERS_UNKNOWN                 0x10
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB             0x20
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_16MB            0x40
#define RTL_USER_PROCESS_PARAMETERS_CASE_SENSITIVE          0x80
#define RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS     0x100
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_1            0x200
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_2            0x400
#define RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH        0x1000
#define RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH          0x2000
#define RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING       0x4000
#define RTL_USER_PROCESS_PARAMETERS_NX                      0x20000

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

//
// End of Exception List
//
#define EXCEPTION_CHAIN_END                                 ((PEXCEPTION_REGISTRATION_RECORD)-1)

//
// Range and Range List Flags
//
#define RTL_RANGE_LIST_ADD_IF_CONFLICT                      0x00000001
#define RTL_RANGE_LIST_ADD_SHARED                           0x00000002

#define RTL_RANGE_SHARED                                    0x01
#define RTL_RANGE_CONFLICT                                  0x02

//
// Activation Context Frame Flags
//
#define RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER \
                                                            0x1

//
// RtlActivateActivationContextEx Flags
//
#define RTL_ACTIVATE_ACTIVATION_CONTEXT_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION \
                                                            0x1

//
// Public Heap Flags
//
#define HEAP_NO_SERIALIZE                                   0x00000001
#define HEAP_GROWABLE                                       0x00000002
#define HEAP_GENERATE_EXCEPTIONS                            0x00000004
#define HEAP_ZERO_MEMORY                                    0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY                          0x00000010
#define HEAP_TAIL_CHECKING_ENABLED                          0x00000020
#define HEAP_FREE_CHECKING_ENABLED                          0x00000040
#define HEAP_DISABLE_COALESCE_ON_FREE                       0x00000080
#define HEAP_CREATE_ALIGN_16                                0x00010000
#define HEAP_CREATE_ENABLE_TRACING                          0x00020000
#define HEAP_CREATE_ENABLE_EXECUTE                          0x00040000

//
// User-Defined Heap Flags and Classes
//
#define HEAP_SETTABLE_USER_VALUE                            0x00000100
#define HEAP_SETTABLE_USER_FLAG1                            0x00000200
#define HEAP_SETTABLE_USER_FLAG2                            0x00000400
#define HEAP_SETTABLE_USER_FLAG3                            0x00000800
#define HEAP_SETTABLE_USER_FLAGS                            0x00000E00
#define HEAP_CLASS_0                                        0x00000000
#define HEAP_CLASS_1                                        0x00001000
#define HEAP_CLASS_2                                        0x00002000
#define HEAP_CLASS_3                                        0x00003000
#define HEAP_CLASS_4                                        0x00004000
#define HEAP_CLASS_5                                        0x00005000
#define HEAP_CLASS_6                                        0x00006000
#define HEAP_CLASS_7                                        0x00007000
#define HEAP_CLASS_8                                        0x00008000
#define HEAP_CLASS_MASK                                     0x0000F000

//
// Internal HEAP Structure Flags
//
#define HEAP_FLAG_PAGE_ALLOCS                               0x01000000
#define HEAP_PROTECTION_ENABLED                             0x02000000
#define HEAP_BREAK_WHEN_OUT_OF_VM                           0x04000000
#define HEAP_NO_ALIGNMENT                                   0x08000000
#define HEAP_CAPTURE_STACK_BACKTRACES                       0x08000000
#define HEAP_SKIP_VALIDATION_CHECKS                         0x10000000
#define HEAP_VALIDATE_ALL_ENABLED                           0x20000000
#define HEAP_VALIDATE_PARAMETERS_ENABLED                    0x40000000
#define HEAP_LOCK_USER_ALLOCATED                            0x80000000

//
// Heap Validation Flags
//
#define HEAP_CREATE_VALID_MASK                              \
    (HEAP_NO_SERIALIZE              |                       \
     HEAP_GROWABLE                  |                       \
     HEAP_GENERATE_EXCEPTIONS       |                       \
     HEAP_ZERO_MEMORY               |                       \
     HEAP_REALLOC_IN_PLACE_ONLY     |                       \
     HEAP_TAIL_CHECKING_ENABLED     |                       \
     HEAP_FREE_CHECKING_ENABLED     |                       \
     HEAP_DISABLE_COALESCE_ON_FREE  |                       \
     HEAP_CLASS_MASK                |                       \
     HEAP_CREATE_ALIGN_16           |                       \
     HEAP_CREATE_ENABLE_TRACING     |                       \
     HEAP_CREATE_ENABLE_EXECUTE)
#ifdef C_ASSERT
C_ASSERT(HEAP_CREATE_VALID_MASK == 0x0007F0FF);
#endif

//
// Native image architecture
//
#if defined(_M_IX86)
#define IMAGE_FILE_MACHINE_NATIVE IMAGE_FILE_MACHINE_I386
#elif defined(_M_ARM)
#define IMAGE_FILE_MACHINE_NATIVE IMAGE_FILE_MACHINE_ARM
#elif defined(_M_AMD64)
#define IMAGE_FILE_MACHINE_NATIVE IMAGE_FILE_MACHINE_AMD64
#else
#error Define these please!
#endif

//
// Registry Keys
//
#define RTL_REGISTRY_ABSOLUTE                               0
#define RTL_REGISTRY_SERVICES                               1
#define RTL_REGISTRY_CONTROL                                2
#define RTL_REGISTRY_WINDOWS_NT                             3
#define RTL_REGISTRY_DEVICEMAP                              4
#define RTL_REGISTRY_USER                                   5
#define RTL_REGISTRY_MAXIMUM                                6
#define RTL_REGISTRY_HANDLE                                 0x40000000
#define RTL_REGISTRY_OPTIONAL                               0x80000000
#define RTL_QUERY_REGISTRY_SUBKEY                           0x00000001
#define RTL_QUERY_REGISTRY_TOPKEY                           0x00000002
#define RTL_QUERY_REGISTRY_REQUIRED                         0x00000004
#define RTL_QUERY_REGISTRY_NOVALUE                          0x00000008
#define RTL_QUERY_REGISTRY_NOEXPAND                         0x00000010
#define RTL_QUERY_REGISTRY_DIRECT                           0x00000020
#define RTL_QUERY_REGISTRY_DELETE                           0x00000040

//
// Versioning
//
#define VER_MINORVERSION                                    0x0000001
#define VER_MAJORVERSION                                    0x0000002
#define VER_BUILDNUMBER                                     0x0000004
#define VER_PLATFORMID                                      0x0000008
#define VER_SERVICEPACKMINOR                                0x0000010
#define VER_SERVICEPACKMAJOR                                0x0000020
#define VER_SUITENAME                                       0x0000040
#define VER_PRODUCT_TYPE                                    0x0000080
#define VER_PLATFORM_WIN32s                                 0
#define VER_PLATFORM_WIN32_WINDOWS                          1
#define VER_PLATFORM_WIN32_NT                               2
#define VER_EQUAL                                           1
#define VER_GREATER                                         2
#define VER_GREATER_EQUAL                                   3
#define VER_LESS                                            4
#define VER_LESS_EQUAL                                      5
#define VER_AND                                             6
#define VER_OR                                              7
#define VER_CONDITION_MASK                                  7
#define VER_NUM_BITS_PER_CONDITION_MASK                     3

//
// Maximum Path Length
//
#define MAX_PATH                                            260

//
// RtlAcquirePrivileges Flags
//
#define RTL_ACQUIRE_PRIVILEGE_IMPERSONATE                   1
#define RTL_ACQUIRE_PRIVILEGE_PROCESS                       2

//
// String Hash Algorithms
//
#define HASH_STRING_ALGORITHM_DEFAULT                       0
#define HASH_STRING_ALGORITHM_X65599                        1
#define HASH_STRING_ALGORITHM_INVALID                       0xffffffff

//
// RtlDuplicateString Flags
//
#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE         1
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING   2

//
// RtlFindCharInUnicodeString Flags
//
#define RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END        1
#define RTL_FIND_CHAR_IN_UNICODE_STRING_COMPLEMENT_CHAR_SET 2
#define RTL_FIND_CHAR_IN_UNICODE_STRING_CASE_INSENSITIVE    4

//
// RtlImageNtHeaderEx Flags
//
#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK          0x00000001

//
// Activation Contexts
//
#define INVALID_ACTIVATION_CONTEXT                          (PVOID)0xFFFFFFFF

//
// C++ CONST casting
//
#if defined(__cplusplus)
#define RTL_CONST_CAST(type)                    const_cast<type>
#else
#define RTL_CONST_CAST(type)                    (type)
#endif

//
// Constant String Macro
//
#define RTL_CONSTANT_STRING(__SOURCE_STRING__)                  \
{                                                               \
    sizeof(__SOURCE_STRING__) - sizeof((__SOURCE_STRING__)[0]), \
    sizeof(__SOURCE_STRING__),                                  \
    (__SOURCE_STRING__)                                         \
}

//
// Constant Object Attributes Macro
//
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)                    \
{                                                               \
    sizeof(OBJECT_ATTRIBUTES),                                  \
    NULL,                                                       \
    RTL_CONST_CAST(PUNICODE_STRING)(n),                         \
    a,                                                          \
    NULL,                                                       \
    NULL                                                        \
}

#define RTL_INIT_OBJECT_ATTRIBUTES(n, a)                        \
    RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)

//
// Boot Status Data Field Types
//
typedef enum _RTL_BSD_ITEM_TYPE
{
    RtlBsdItemVersionNumber,
    RtlBsdItemProductType,
    RtlBsdItemAabEnabled,
    RtlBsdItemAabTimeout,
    RtlBsdItemBootGood,
    RtlBsdItemBootShutdown,
    RtlBsdItemMax
} RTL_BSD_ITEM_TYPE, *PRTL_BSD_ITEM_TYPE;

//
// Table and Compare result types
//
typedef enum _TABLE_SEARCH_RESULT
{
    TableEmptyTree,
    TableFoundNode,
    TableInsertAsLeft,
    TableInsertAsRight
} TABLE_SEARCH_RESULT;

typedef enum _RTL_GENERIC_COMPARE_RESULTS
{
    GenericLessThan,
    GenericGreaterThan,
    GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;

//
// RTL Path Types
//
typedef enum _RTL_PATH_TYPE
{
    RtlPathTypeUnknown,
    RtlPathTypeUncAbsolute,
    RtlPathTypeDriveAbsolute,
    RtlPathTypeDriveRelative,
    RtlPathTypeRooted,
    RtlPathTypeRelative,
    RtlPathTypeLocalDevice,
    RtlPathTypeRootLocalDevice,
} RTL_PATH_TYPE;

//
// Unhandled Exception Filter
//
typedef ULONG
(NTAPI *RTLP_UNHANDLED_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *ExceptionInfo);
typedef RTLP_UNHANDLED_EXCEPTION_FILTER *PRTLP_UNHANDLED_EXCEPTION_FILTER;

//
// Thread and Process Start Routines for RtlCreateUserThread/Process
//
typedef ULONG (NTAPI *PTHREAD_START_ROUTINE)(PVOID Parameter);

typedef VOID
(NTAPI *PRTL_BASE_PROCESS_START_ROUTINE)(PTHREAD_START_ROUTINE StartAddress, PVOID Parameter);

//
// Worker Start/Exit Function
//
typedef NTSTATUS
(NTAPI *PRTL_START_POOL_THREAD)(PTHREAD_START_ROUTINE Function, PVOID Parameter,
                                PHANDLE ThreadHandle);

typedef NTSTATUS
(NTAPI *PRTL_EXIT_POOL_THREAD)(NTSTATUS ExitStatus);

//
// Declare empty structure definitions so that they may be referenced by
// routines before they are defined
//
struct _RTL_AVL_TABLE;
struct _RTL_GENERIC_TABLE;
struct _RTL_RANGE;

//
// Routines and callbacks for the RTL AVL/Generic Table package
//
typedef NTSTATUS
(NTAPI RTL_AVL_MATCH_FUNCTION)(struct _RTL_AVL_TABLE *Table, PVOID UserData, PVOID MatchData);
typedef RTL_AVL_MATCH_FUNCTION *PRTL_AVL_MATCH_FUNCTION;

typedef RTL_GENERIC_COMPARE_RESULTS
(NTAPI RTL_AVL_COMPARE_ROUTINE) (struct _RTL_AVL_TABLE *Table, PVOID FirstStruct, PVOID SecondStruct);
typedef RTL_AVL_COMPARE_ROUTINE *PRTL_AVL_COMPARE_ROUTINE;

typedef RTL_GENERIC_COMPARE_RESULTS
(NTAPI RTL_GENERIC_COMPARE_ROUTINE) (struct _RTL_GENERIC_TABLE *Table, PVOID FirstStruct, PVOID SecondStruct);
typedef RTL_GENERIC_COMPARE_ROUTINE *PRTL_GENERIC_COMPARE_ROUTINE;

typedef PVOID
(NTAPI RTL_GENERIC_ALLOCATE_ROUTINE) (struct _RTL_GENERIC_TABLE *Table, CLONG ByteSize);
typedef RTL_GENERIC_ALLOCATE_ROUTINE *PRTL_GENERIC_ALLOCATE_ROUTINE;

typedef PVOID
(NTAPI RTL_AVL_ALLOCATE_ROUTINE) (struct _RTL_AVL_TABLE *Table, CLONG ByteSize);
typedef RTL_AVL_ALLOCATE_ROUTINE *PRTL_AVL_ALLOCATE_ROUTINE;

typedef VOID
(NTAPI RTL_GENERIC_FREE_ROUTINE) (struct _RTL_GENERIC_TABLE *Table, PVOID Buffer);
typedef RTL_GENERIC_FREE_ROUTINE *PRTL_GENERIC_FREE_ROUTINE;

typedef VOID
(NTAPI RTL_AVL_FREE_ROUTINE) (struct _RTL_AVL_TABLE *Table, PVOID Buffer);
typedef RTL_AVL_FREE_ROUTINE *PRTL_AVL_FREE_ROUTINE;

#ifdef RTL_USE_AVL_TABLES
#undef  RTL_GENERIC_COMPARE_ROUTINE
#undef PRTL_GENERIC_COMPARE_ROUTINE
#undef  RTL_GENERIC_ALLOCATE_ROUTINE
#undef PRTL_GENERIC_ALLOCATE_ROUTINE
#undef  RTL_GENERIC_FREE_ROUTINE
#undef PRTL_GENERIC_FREE_ROUTINE

#define  RTL_GENERIC_COMPARE_ROUTINE     RTL_AVL_COMPARE_ROUTINE
#define PRTL_GENERIC_COMPARE_ROUTINE    PRTL_AVL_COMPARE_ROUTINE
#define  RTL_GENERIC_ALLOCATE_ROUTINE    RTL_AVL_ALLOCATE_ROUTINE
#define PRTL_GENERIC_ALLOCATE_ROUTINE   PRTL_AVL_ALLOCATE_ROUTINE
#define  RTL_GENERIC_FREE_ROUTINE        RTL_AVL_FREE_ROUTINE
#define PRTL_GENERIC_FREE_ROUTINE       PRTL_AVL_FREE_ROUTINE
#endif /* RTL_USE_AVL_TABLES */

//
// Custom Heap Commit Routine for RtlCreateHeap
//
typedef NTSTATUS
(NTAPI * PRTL_HEAP_COMMIT_ROUTINE)(PVOID Base, PVOID *CommitAddress, PSIZE_T CommitSize);

//
// Parameters for RtlCreateHeap
//
typedef struct _RTL_HEAP_PARAMETERS
{
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

//
// RTL Bitmap structures
//
typedef struct _RTL_BITMAP
{
    ULONG SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

typedef struct _RTL_BITMAP_RUN
{
    ULONG StartingIndex;
    ULONG NumberOfBits;
} RTL_BITMAP_RUN, *PRTL_BITMAP_RUN;

//
// RtlGenerateXxxName context
//
typedef struct _GENERATE_NAME_CONTEXT
{
    USHORT Checksum;
    BOOLEAN CheckSumInserted;
    UCHAR NameLength;
    WCHAR NameBuffer[8];
    ULONG ExtensionLength;
    WCHAR ExtensionBuffer[4];
    ULONG LastIndexValue;
} GENERATE_NAME_CONTEXT, *PGENERATE_NAME_CONTEXT;

//
// RTL Splay and Balanced Links structures
//
typedef struct _RTL_SPLAY_LINKS
{
    struct _RTL_SPLAY_LINKS *Parent;
    struct _RTL_SPLAY_LINKS *LeftChild;
    struct _RTL_SPLAY_LINKS *RightChild;
} RTL_SPLAY_LINKS, *PRTL_SPLAY_LINKS;

typedef struct _RTL_BALANCED_LINKS
{
    struct _RTL_BALANCED_LINKS *Parent;
    struct _RTL_BALANCED_LINKS *LeftChild;
    struct _RTL_BALANCED_LINKS *RightChild;
    CHAR Balance;
    UCHAR Reserved[3];
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

//
// RTL Avl/Generic Tables
//
#ifndef RTL_USE_AVL_TABLES
typedef struct _RTL_GENERIC_TABLE
{
    PRTL_SPLAY_LINKS TableRoot;
    LIST_ENTRY InsertOrderList;
    PLIST_ENTRY OrderedPointer;
    ULONG WhichOrderedElement; ULONG NumberGenericTableElements;
    PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine;
    PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_GENERIC_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
} RTL_GENERIC_TABLE, *PRTL_GENERIC_TABLE;
#endif /* !RTL_USE_AVL_TABLES */

typedef struct _RTL_AVL_TABLE
{
    RTL_BALANCED_LINKS BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    PRTL_BALANCED_LINKS RestartKey;
    ULONG DeleteCount;
    PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
    PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_AVL_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

#ifdef RTL_USE_AVL_TABLES
#undef  RTL_GENERIC_TABLE
#undef PRTL_GENERIC_TABLE

#define  RTL_GENERIC_TABLE  RTL_AVL_TABLE
#define PRTL_GENERIC_TABLE PRTL_AVL_TABLE
#endif /* RTL_USE_AVL_TABLES */

//
// RTL Compression Buffer
//
typedef struct _COMPRESSED_DATA_INFO {
    USHORT CompressionFormatAndEngine;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved;
    USHORT NumberOfChunks;
    ULONG CompressedChunkSizes[ANYSIZE_ARRAY];
} COMPRESSED_DATA_INFO, *PCOMPRESSED_DATA_INFO;

//
// Time Structure for RTL Time calls
//
typedef struct _TIME_FIELDS
{
    CSHORT Year;
    CSHORT Month;
    CSHORT Day;
    CSHORT Hour;
    CSHORT Minute;
    CSHORT Second;
    CSHORT Milliseconds;
    CSHORT Weekday;
} TIME_FIELDS, *PTIME_FIELDS;

//
// Activation Context
//
typedef PVOID PACTIVATION_CONTEXT;

//
// Activation Context Frame
//
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC
{
    SIZE_T Size;
    ULONG Format;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC, *PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC;

typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED
{
    SIZE_T Size;
    ULONG Format;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
    PVOID Extra1;
    PVOID Extra2;
    PVOID Extra3;
    PVOID Extra4;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED, *PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED;

typedef RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME;
typedef PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME;

#if (NTDDI_VERSION >= NTDDI_WS03)
typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags; ULONG NextCookieSequenceNumber; ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;
#else
typedef struct _ACTIVATION_CONTEXT_STACK
{
    ULONG Flags;
    ULONG NextCookieSequenceNumber; PVOID ActiveFrame;
    LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;
#endif

//
// Information Structures for RTL Debug Functions
//
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
    ULONG NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageCheckSum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

typedef struct _RTL_HEAP_TAG_INFO
{
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
} RTL_HEAP_TAG_INFO, *PRTL_HEAP_TAG_INFO;

typedef struct _RTL_HEAP_USAGE_ENTRY
{
    struct _RTL_HEAP_USAGE_ENTRY *Next;
    PVOID Address;
    SIZE_T Size;
    USHORT AllocatorBackTraceIndex;
    USHORT TagIndex;
} RTL_HEAP_USAGE_ENTRY, *PRTL_HEAP_USAGE_ENTRY;

typedef struct _RTL_HEAP_USAGE
{
    ULONG Length;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    SIZE_T BytesReserved;
    SIZE_T BytesReservedMaximum;
    PRTL_HEAP_USAGE_ENTRY Entries;
    PRTL_HEAP_USAGE_ENTRY AddedEntries;
    PRTL_HEAP_USAGE_ENTRY RemovedEntries;
    ULONG_PTR Reserved[8];
} RTL_HEAP_USAGE, *PRTL_HEAP_USAGE;

typedef struct _RTL_HEAP_WALK_ENTRY
{ PVOID DataAddress;
    SIZE_T DataSize;
    UCHAR OverheadBytes;
    UCHAR SegmentIndex;
    USHORT Flags;
    union
    {
        struct
        {
            SIZE_T Settable;
            USHORT TagIndex;
            USHORT AllocatorBackTraceIndex;
            ULONG Reserved[2];
        } Block;
        struct
        {
            ULONG_PTR CommittedSize;
            ULONG_PTR UnCommittedSize;
            PVOID FirstEntry;
            PVOID LastEntry;
        } Segment;
    };
} RTL_HEAP_WALK_ENTRY, *PRTL_HEAP_WALK_ENTRY;

typedef struct _RTL_HEAP_ENTRY
{
    SIZE_T Size;
    USHORT Flags;
    USHORT AllocatorBackTraceIndex;
    union
    {
        struct
        {
            SIZE_T Settable;
            ULONG Tag;
        } s1;
        struct
        {
            SIZE_T CommittedSize;
            PVOID FirstBlock;
        } s2;
    } u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;

typedef struct _RTL_HEAP_TAG
{
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
    USHORT TagIndex;
    USHORT CreatorBackTraceIndex;
    WCHAR TagName[24];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;

typedef struct _RTL_HEAP_INFORMATION
{ PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[4];
    PRTL_HEAP_TAG Tags;
    PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION, *PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS
{
    ULONG NumberOfHeaps;
    RTL_HEAP_INFORMATION Heaps[1];
} RTL_PROCESS_HEAPS, *PRTL_PROCESS_HEAPS;

typedef struct _RTL_PROCESS_LOCK_INFORMATION
{
    PVOID Address;
    USHORT Type;
    USHORT CreatorBackTraceIndex;
    ULONG OwnerThreadId;
    ULONG ActiveCount;
    ULONG ContentionCount;
    ULONG EntryCount;
    ULONG RecursionCount;
    ULONG NumberOfSharedWaiters;
    ULONG NumberOfExclusiveWaiters;
} RTL_PROCESS_LOCK_INFORMATION, *PRTL_PROCESS_LOCK_INFORMATION;

typedef struct _RTL_PROCESS_LOCKS
{
    ULONG NumberOfLocks;
    RTL_PROCESS_LOCK_INFORMATION Locks[1];
} RTL_PROCESS_LOCKS, *PRTL_PROCESS_LOCKS;

typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION
{ PVOID SymbolicBackTrace;
    ULONG TraceCount;
    USHORT Index;
    USHORT Depth;
    PVOID BackTrace[16];
} RTL_PROCESS_BACKTRACE_INFORMATION, *PRTL_PROCESS_BACKTRACE_INFORMATION;

typedef struct _RTL_PROCESS_BACKTRACES
{
    ULONG CommittedMemory;
    ULONG ReservedMemory;
    ULONG NumberOfBackTraceLookups;
    ULONG NumberOfBackTraces;
    RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
} RTL_PROCESS_BACKTRACES, *PRTL_PROCESS_BACKTRACES;

typedef struct _RTL_PROCESS_VERIFIER_OPTIONS
{
    ULONG SizeStruct;
    ULONG Option;
    UCHAR OptionData[1];
    //
    // Option array continues below
    //
} RTL_PROCESS_VERIFIER_OPTIONS, *PRTL_PROCESS_VERIFIER_OPTIONS;

typedef struct _RTL_DEBUG_INFORMATION
{
    HANDLE SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    ULONG ViewBaseDelta;
    HANDLE EventPairClient;
    PVOID EventPairTarget;
    HANDLE TargetProcessId;
    HANDLE TargetThreadHandle;
    ULONG Flags;
    ULONG OffsetFree;
    ULONG CommitSize;
    ULONG ViewSize;
    union
    {
        PRTL_PROCESS_MODULES Modules;
        PRTL_PROCESS_MODULE_INFORMATION_EX ModulesEx;
    };
    PRTL_PROCESS_BACKTRACES BackTraces;
    PRTL_PROCESS_HEAPS Heaps;
    PRTL_PROCESS_LOCKS Locks;
    HANDLE SpecificHeap;
    HANDLE TargetProcessHandle;
    RTL_PROCESS_VERIFIER_OPTIONS VerifierOptions;
    HANDLE ProcessHeap;
    HANDLE CriticalSectionHandle;
    HANDLE CriticalSectionOwnerThread;
    PVOID Reserved[4];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;

//
// Unload Event Trace Structure for RtlGetUnloadEventTrace
//
typedef struct _RTL_UNLOAD_EVENT_TRACE
{ PVOID BaseAddress;
    ULONG SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
} RTL_UNLOAD_EVENT_TRACE, *PRTL_UNLOAD_EVENT_TRACE;

//
// RTL Handle Structures
//
typedef struct _RTL_HANDLE_TABLE_ENTRY
{
    union
    {
        ULONG Flags;
        struct _RTL_HANDLE_TABLE_ENTRY *NextFree;
    };
} RTL_HANDLE_TABLE_ENTRY, *PRTL_HANDLE_TABLE_ENTRY;

typedef struct _RTL_HANDLE_TABLE
{
    ULONG MaximumNumberOfHandles;
    ULONG SizeOfHandleTableEntry; ULONG Reserved[2];
    PRTL_HANDLE_TABLE_ENTRY FreeHandles;
    PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
} RTL_HANDLE_TABLE, *PRTL_HANDLE_TABLE;

//
// Current Directory Structures
//
typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTLP_CURDIR_REF
{ LONG RefCount;
    HANDLE Handle;
} RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_PERTHREAD_CURDIR
{
    PRTL_DRIVE_LETTER_CURDIR CurrentDirectories;
    PUNICODE_STRING ImageName; PVOID Environment;
} RTL_PERTHREAD_CURDIR, *PRTL_PERTHREAD_CURDIR;

//
// Private State structure for RtlAcquirePrivilege/RtlReleasePrivilege
//
typedef struct _RTL_ACQUIRE_STATE
{
    HANDLE Token;
    HANDLE OldImpersonationToken;
    PTOKEN_PRIVILEGES OldPrivileges;
    PTOKEN_PRIVILEGES NewPrivileges;
    ULONG Flags;
    UCHAR OldPrivBuffer[1024];
} RTL_ACQUIRE_STATE, *PRTL_ACQUIRE_STATE;

#if 0
typedef struct _RTL_CRITICAL_SECTION
{
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore; ULONG_PTR SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
#endif

//
// RTL Range List Structures
//
typedef struct _RTL_RANGE_LIST
{
    LIST_ENTRY ListHead;
    ULONG Flags; ULONG Count; ULONG Stamp;
} RTL_RANGE_LIST, *PRTL_RANGE_LIST;

typedef struct _RTL_RANGE
{
    ULONGLONG Start;
    ULONGLONG End;
    PVOID UserData;
    PVOID Owner;
    UCHAR Attributes;
    UCHAR Flags;
} RTL_RANGE, *PRTL_RANGE;

typedef struct _RANGE_LIST_ITERATOR
{
    PLIST_ENTRY RangeListHead;
    PLIST_ENTRY MergedHead;
    PVOID Current;
    ULONG Stamp;
} RTL_RANGE_LIST_ITERATOR, *PRTL_RANGE_LIST_ITERATOR;

typedef struct _RTL_USER_PROCESS_INFORMATION
{
    ULONG Size;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

//
// Rtl Atom
//
typedef USHORT RTL_ATOM, *PRTL_ATOM;

//
// RTL Atom Table Structures
//
typedef struct _RTL_ATOM_TABLE_ENTRY
{
    struct _RTL_ATOM_TABLE_ENTRY *HashLink;
    USHORT HandleIndex;
    USHORT Atom;
    USHORT ReferenceCount;
    UCHAR Flags;
    UCHAR NameLength;
    WCHAR Name[1];
} RTL_ATOM_TABLE_ENTRY, *PRTL_ATOM_TABLE_ENTRY;

typedef struct _RTL_ATOM_TABLE
{
    ULONG Signature;
    union {
        RTL_CRITICAL_SECTION CriticalSection;
    };
    union {
        RTL_HANDLE_TABLE RtlHandleTable;
    };
    ULONG NumberOfBuckets;
    PRTL_ATOM_TABLE_ENTRY Buckets[1];
} RTL_ATOM_TABLE, *PRTL_ATOM_TABLE;

#ifndef _WINBASE_
//
// System Time and Timezone Structures
//
typedef struct _SYSTEMTIME
{
    USHORT wYear;
    USHORT wMonth;
    USHORT wDayOfWeek;
    USHORT wDay;
    USHORT wHour;
    USHORT wMinute;
    USHORT wSecond;
    USHORT wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;
#endif

//
// Hotpatch Header
//
typedef struct _RTL_PATCH_HEADER
{
    LIST_ENTRY PatchList;
    PVOID PatchImageBase;
    struct _RTL_PATCH_HEADER *NextPath;
    ULONG PatchFlags; LONG PatchRefCount;
    struct _HOTPATCH_HEADER *HotpatchHeader;
    UNICODE_STRING TargetDllName;
    PVOID TargetDllBase;
    PLDR_DATA_TABLE_ENTRY TargetLdrDataTableEntry;
    PLDR_DATA_TABLE_ENTRY PatchLdrDataTableEntry;
    struct _SYSTEM_HOTPATCH_CODE_INFORMATION *CodeInfo;
} RTL_PATCH_HEADER, *PRTL_PATCH_HEADER;

//
// Stack Traces
//
typedef struct _RTL_STACK_TRACE_ENTRY
{
    struct _RTL_STACK_TRACE_ENTRY *HashChain;
    ULONG TraceCount;
    USHORT Index;
    USHORT Depth;
    PVOID BackTrace[32];
} RTL_STACK_TRACE_ENTRY, *PRTL_STACK_TRACE_ENTRY;

typedef struct _STACK_TRACE_DATABASE
{
    RTL_CRITICAL_SECTION CriticalSection;
} STACK_TRACE_DATABASE, *PSTACK_TRACE_DATABASE;

typedef struct _RTL_TRACE_BLOCK
{
    ULONG Magic;
    ULONG Count;
    ULONG Size;
    ULONG UserCount;
    ULONG UserSize;
    PVOID UserContext;
    struct _RTL_TRACE_BLOCK *Next;
    PVOID *Trace;
} RTL_TRACE_BLOCK, *PRTL_TRACE_BLOCK;

//
// KUSER_SHARED_DATA location in User Mode
//
#define USER_SHARED_DATA                        (0x7FFE0000)

//
// Global Flags
//
#define FLG_STOP_ON_EXCEPTION                   0x00000001
#define FLG_SHOW_LDR_SNAPS                      0x00000002
#define FLG_DEBUG_INITIAL_COMMAND               0x00000004
#define FLG_STOP_ON_HUNG_GUI                    0x00000008
#define FLG_HEAP_ENABLE_TAIL_CHECK              0x00000010
#define FLG_HEAP_ENABLE_FREE_CHECK              0x00000020
#define FLG_HEAP_VALIDATE_PARAMETERS            0x00000040
#define FLG_HEAP_VALIDATE_ALL                   0x00000080
#define FLG_POOL_ENABLE_TAIL_CHECK              0x00000100
#define FLG_POOL_ENABLE_FREE_CHECK              0x00000200
#define FLG_POOL_ENABLE_TAGGING                 0x00000400
#define FLG_HEAP_ENABLE_TAGGING                 0x00000800
#define FLG_USER_STACK_TRACE_DB                 0x00001000
#define FLG_KERNEL_STACK_TRACE_DB               0x00002000
#define FLG_MAINTAIN_OBJECT_TYPELIST            0x00004000
#define FLG_HEAP_ENABLE_TAG_BY_DLL              0x00008000
#define FLG_IGNORE_DEBUG_PRIV                   0x00010000
#define FLG_ENABLE_CSRDEBUG                     0x00020000
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD           0x00040000
#define FLG_DISABLE_PAGE_KERNEL_STACKS          0x00080000
#if (NTDDI_VERSION < NTDDI_WINXP)
#define FLG_HEAP_ENABLE_CALL_TRACING            0x00100000
#else
#define FLG_ENABLE_SYSTEM_CRIT_BREAKS           0x00100000
#endif
#define FLG_HEAP_DISABLE_COALESCING             0x00200000
#define FLG_ENABLE_CLOSE_EXCEPTIONS             0x00400000
#define FLG_ENABLE_EXCEPTION_LOGGING            0x00800000
#define FLG_ENABLE_HANDLE_TYPE_TAGGING          0x01000000
#define FLG_HEAP_PAGE_ALLOCS                    0x02000000
#define FLG_DEBUG_INITIAL_COMMAND_EX            0x04000000
#define FLG_VALID_BITS                          0x07FFFFFF

//
// Flags for NtCreateProcessEx
//
#define PROCESS_CREATE_FLAGS_BREAKAWAY          0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT   0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES    0x00000004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES        0x00000010

//
// Process priority classes
//
#define PROCESS_PRIORITY_CLASS_INVALID          0
#define PROCESS_PRIORITY_CLASS_IDLE             1
#define PROCESS_PRIORITY_CLASS_NORMAL           2
#define PROCESS_PRIORITY_CLASS_HIGH             3
#define PROCESS_PRIORITY_CLASS_REALTIME         4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL     5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL     6

//
// NtCreateProcessEx flags
//
#define PS_REQUEST_BREAKAWAY                    1
#define PS_NO_DEBUG_INHERIT                     2
#define PS_INHERIT_HANDLES                      4
#define PS_LARGE_PAGES                          8
#define PS_ALL_FLAGS                            (PS_REQUEST_BREAKAWAY | \
                                                 PS_NO_DEBUG_INHERIT  | \
                                                 PS_INHERIT_HANDLES   | \
                                                 PS_LARGE_PAGES)

//
// Process base priorities
//
#define PROCESS_PRIORITY_IDLE                   3
#define PROCESS_PRIORITY_NORMAL                 8
#define PROCESS_PRIORITY_NORMAL_FOREGROUND      9

//
// Process memory priorities
//
#define MEMORY_PRIORITY_BACKGROUND             0
#define MEMORY_PRIORITY_UNKNOWN                1
#define MEMORY_PRIORITY_FOREGROUND             2

//
// Process Priority Separation Values (OR)
//
#define PSP_VARIABLE_QUANTUMS                   4
#define PSP_LONG_QUANTUMS                       16

//
// TLS/FLS Defines
//
#define TLS_EXPANSION_SLOTS                     1024

//
// Thread Native Base Priorities
//
#define LOW_PRIORITY                            0
#define LOW_REALTIME_PRIORITY                   16
#define HIGH_PRIORITY                           31
#define MAXIMUM_PRIORITY                        32

//
// Process/Thread/Job Information Classes for NtQueryInformationProcess/Thread/Job
//
typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    MaxThreadInfoClass
} THREADINFOCLASS;

//
// Initial TEB
//
typedef struct _INITIAL_TEB {
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackCommit;
    PVOID StackCommitMax;
    PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

//
// TEB Active Frame Structures
//
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    LPSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct _CLIENT_ID32
{
    ULONG UniqueProcess;
    ULONG UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

typedef struct _CLIENT_ID64
{
    ULONG64 UniqueProcess;
    ULONG64 UniqueThread;
} CLIENT_ID64, *PCLIENT_ID64;

//
// PEB Free Block Descriptor
//
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* Next;
    ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG AllocationSize;
    ULONG Size;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWSTR Environment;
    ULONG dwX;
    ULONG dwY;
    ULONG dwXSize;
    ULONG dwYSize;
    ULONG dwXCountChars;
    ULONG dwYCountChars;
    ULONG dwFillAttribute;
    ULONG dwFlags;
    ULONG wShowWindow;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING Desktop;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeInfo;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define GDI_HANDLE_BUFFER_SIZE 60
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
#if (NTDDI_VERSION >= NTDDI_WS03)
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages:1;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
            BOOLEAN IsProtectedProcess:1;
            BOOLEAN IsLegacyProcess:1;
            BOOLEAN IsImageDynamicallyRelocated:1;
            BOOLEAN SkipPatchingUser32Forwarders:1;
            BOOLEAN SpareBits:3;
#else
            BOOLEAN SpareBits:7;
#endif
        };
    };
#else
     BOOLEAN SpareBool;
#endif
    VOID *Reserved1;
    VOID *ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    VOID *SubSystemData;
    VOID *ProcessHeap;
    struct _RTL_CRITICAL_SECTION* FastPebLock;
#if (NTDDI_VERSION >= NTDDI_WS03)
    VOID *AltThunkSListPtr;
    VOID *SparePtr2;
    ULONG EnvironmentUpdateCount;
    VOID *KernelCallbackTable;
#else
    PPEBLOCKROUTINE FastPebLockRoutine;
    PPEBLOCKROUTINE FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    VOID *KernelCallbackTable;
#endif
    ULONG SystemReserved[1];
    ULONG SpareUlong;
    // AtlThunkSListPtr32
    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    VOID *TlsBitmap;
    ULONG TlsBitmapBits[2];
    VOID *ReadOnlySharedMemoryBase;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    VOID *HotpatchInformation;
#else
    VOID *ReadOnlySharedMemoryHeap;
#endif
    VOID **ReadOnlyStaticServerData;
    VOID *AnsiCodePageData;
    VOID *OemCodePageData;
    VOID *UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG_PTR HeapSegmentReserve;
    ULONG_PTR HeapSegmentCommit;
    ULONG_PTR HeapDeCommitTotalFreeThreshold;
    ULONG_PTR HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    VOID **ProcessHeaps;
    PVOID Reserved7[2];
    ULONG Reserved8;
    RTL_CRITICAL_SECTION **LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR *ImageProcessAffinityMask;
    PVOID Reserved9[33];
    VOID *TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
} PEB, *PPEB;

//
// Process Information Structures for NtQueryProcessInformation
//
typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_ACCESS_TOKEN
{
    HANDLE Token;
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef struct _PROCESS_DEVICEMAP_INFORMATION
{
    union
    {
        struct
        {
            HANDLE DirectoryHandle;
        } Set;
        struct
        {
            ULONG DriveMap;
            UCHAR DriveType[32];
        } Query;
    };
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

typedef struct _KERNEL_USER_TIMES
{
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef struct _POOLED_USAGE_AND_LIMITS
{
    SIZE_T PeakPagedPoolUsage;
    SIZE_T PagedPoolUsage;
    SIZE_T PagedPoolLimit;
    SIZE_T PeakNonPagedPoolUsage;
    SIZE_T NonPagedPoolUsage;
    SIZE_T NonPagedPoolLimit;
    SIZE_T PeakPagefileUsage;
    SIZE_T PagefileUsage;
    SIZE_T PagefileLimit;
} POOLED_USAGE_AND_LIMITS, *PPOOLED_USAGE_AND_LIMITS;

typedef struct _PROCESS_SESSION_INFORMATION
{
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef struct _PROCESS_PRIORITY_CLASS
{
    BOOLEAN Foreground;
    UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

typedef struct _PROCESS_FOREGROUND_BACKGROUND
{
    BOOLEAN Foreground;
} PROCESS_FOREGROUND_BACKGROUND, *PPROCESS_FOREGROUND_BACKGROUND;

//
// Thread Information Structures for NtQueryProcessInformation
//
typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

/* SystemTime [out]: A pointer to a LARGE_INTEGER structure 
                     that receives the system time. 
   This value means number of 100-nanosecond units since 1600, 1 January. 
   Time is incremented 10.000.000 times per second.,i.e 1s=10.000.000
*/
NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER SystemTime);

/* NtSetSystemTime() is similar to NtQuerySystemTime()
   STATUS_SUCCESS is returned if the service is successfully executed.
   STATUS_PRIVILEGE_NOT_HELD is returned if the caller does not have the privilege
     to set the system time.
   STATUS_ACCESS_VIOLATION is returned if the input parameter for the system time 
     cannot be read or the output parameter for the system time cannot be written.
   STATUS_INVALID_PARAMETER is returned if the input system time is negative.
 
   SeSystemtimePrivilege is required to set the system time!!!
*/
NTSTATUS NTAPI NtSetSystemTime(PLARGE_INTEGER SystemTime,
                               PLARGE_INTEGER PreviousTime);

//
// Native Calls (Miscellaneous)
//
NTSTATUS NTAPI LdrDisableThreadCalloutsForDll(PVOID BaseAddress);
ULONG NTAPI NtGetTickCount(VOID);
NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);

//
// Native Calls (Virtual Memory Manager)
//
NTSTATUS NTAPI NtAreMappedFilesTheSame(PVOID File1MappedAsAnImage, PVOID File2MappedAsFile);
NTSTATUS NTAPI NtAllocateUserPhysicalPages(HANDLE ProcessHandle, PULONG_PTR NumberOfPages, PULONG_PTR UserPfnArray);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG ProtectionFlags);
NTSTATUS NTAPI NtCreateSection(HANDLE*,ACCESS_MASK,const OBJECT_ATTRIBUTES*,const LARGE_INTEGER*,ULONG,ULONG, HANDLE);
NTSTATUS NTAPI NtExtendSection(HANDLE SectionHandle, PLARGE_INTEGER NewMaximumSize);
NTSTATUS NTAPI NtFlushVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, IO_STATUS_BLOCK *IoStatus);
NTSTATUS NTAPI NtFreeUserPhysicalPages(HANDLE ProcessHandle, PULONG_PTR NumberOfPages, PULONG_PTR UserPfnArray);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
NTSTATUS NTAPI NtGetWriteWatch(HANDLE ProcessHandle, ULONG Flags, PVOID BaseAddress, SIZE_T RegionSize, PVOID *UserAddressArray,
                               PULONG_PTR EntriesInUserAddressArray, PULONG Granularity);
NTSTATUS NTAPI NtLockVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType);
NTSTATUS NTAPI NtMapUserPhysicalPages(PVOID VirtualAddresses, ULONG_PTR NumberOfPages, PULONG_PTR UserPfnArray);
NTSTATUS NTAPI NtMapUserPhysicalPagesScatter(PVOID *VirtualAddresses, ULONG_PTR NumberOfPages, PULONG_PTR UserPfnArray);
NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, VOID **, ULONG, SIZE_T, const LARGE_INTEGER*, SIZE_T*, SECTION_INHERIT, ULONG, ULONG);
NTSTATUS NTAPI NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE,PVOID*,SIZE_T*,ULONG,ULONG*);
NTSTATUS NTAPI NtQuerySection(HANDLE,SECTION_INFORMATION_CLASS,PVOID,ULONG,PULONG);
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE,PVOID,MEMORY_INFORMATION_CLASS,PVOID,ULONG,PULONG);
NTSTATUS NTAPI NtReadVirtualMemory(HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);
NTSTATUS NTAPI NtResetWriteWatch(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize);
NTSTATUS NTAPI NtUnlockVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,PSIZE_T NumberOfBytesToUnlock, ULONG MapType);
NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, VOID *BaseAddress);
NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE,void*,const void*,SIZE_T,SIZE_T*);

//
// Native Calls (Object Manager)
//
NTSTATUS NTAPI NtClose(HANDLE Handle);

NTSTATUS NTAPI NtCloseObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose);

NTSTATUS NTAPI NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtCreateSymbolicLinkObject(PHANDLE SymbolicLinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING Name);

NTSTATUS NTAPI NtDeleteObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose);

NTSTATUS NTAPI NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

NTSTATUS NTAPI NtMakePermanentObject(HANDLE Object);

NTSTATUS NTAPI NtMakeTemporaryObject(HANDLE Handle);

NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtOpenJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtOpenSymbolicLinkObject(PHANDLE SymbolicLinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG BufferLength, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);

NTSTATUS NTAPI NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

NTSTATUS NTAPI NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded);

NTSTATUS NTAPI NtQuerySymbolicLinkObject(HANDLE SymLinkObjHandle, PUNICODE_STRING LinkTarget, PULONG DataWritten);

NTSTATUS NTAPI NtSetInformationObject(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG Length);

NTSTATUS NTAPI NtSetSecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);

NTSTATUS NTAPI NtSignalAndWaitForSingleObject(HANDLE SignalObject, HANDLE WaitObject, BOOLEAN Alertable, PLARGE_INTEGER Time);

NTSTATUS NTAPI NtWaitForMultipleObjects(ULONG Count, HANDLE Object[], WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Time);

NTSTATUS NTAPI NtWaitForMultipleObjects32(ULONG ObjectCount, PLONG Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER TimeOut);

NTSTATUS NTAPI NtWaitForSingleObject(HANDLE Object, BOOLEAN Alertable, PLARGE_INTEGER Time);

//
// Native calls (Kernel Debugger)
//
ULONG DbgPrint(PCSTR Format, ...);

VOID NTAPI DbgBreakPoint(VOID);

NTSTATUS NTAPI NtDebugActiveProcess(HANDLE Process, HANDLE DebugObject);

NTSTATUS NTAPI NtCreateDebugObject(PHANDLE DebugHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);

NTSTATUS NTAPI NtDebugContinue(HANDLE DebugObject, PCLIENT_ID AppClientId, NTSTATUS ContinueStatus);

NTSTATUS NTAPI NtWaitForDebugEvent(HANDLE DebugObject, BOOLEAN Alertable, PLARGE_INTEGER Timeout,
                                   PDBGUI_WAIT_STATE_CHANGE StateChange);

NTSTATUS NTAPI NtRemoveProcessDebug(HANDLE Process, HANDLE DebugObject);

NTSTATUS NTAPI NtSetInformationDebugObject(HANDLE DebugObject, DEBUGOBJECTINFOCLASS InformationClass,
                                           PVOID Information, ULONG InformationLength, PULONG ReturnLength);

NTSTATUS NTAPI NtQueryDebugFilterState(ULONG ComponentId, ULONG Level);

NTSTATUS NTAPI NtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State);

NTSTATUS NTAPI NtSystemDebugControl(SYSDBG_COMMAND ControlCode, PVOID InputBuffer, ULONG InputBufferLength,
                                    PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

//
// Native calls
//
NTSTATUS NTAPI NtAcceptConnectPort(PHANDLE PortHandle, PVOID PortContext, PPORT_MESSAGE ConnectionRequest, BOOLEAN AcceptConnection,
                                   PPORT_VIEW ServerView, PREMOTE_PORT_VIEW ClientView);

NTSTATUS NTAPI NtCompleteConnectPort(HANDLE PortHandle);

NTSTATUS NTAPI NtConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView,
                             PREMOTE_PORT_VIEW ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength);

NTSTATUS NTAPI NtCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG MaxPoolUsage);

NTSTATUS NTAPI NtCreateWaitablePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxConnectInfoLength, ULONG MaxDataLength, ULONG NPMessageQueueSize);

NTSTATUS NTAPI NtImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE ClientMessage);

NTSTATUS NTAPI NtListenPort(HANDLE PortHandle, PPORT_MESSAGE ConnectionRequest);

NTSTATUS NTAPI NtQueryInformationPort(HANDLE PortHandle, PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG PortInformationLength, PULONG ReturnLength);

NTSTATUS NTAPI NtQueryPortInformationProcess(VOID);

NTSTATUS NTAPI NtReadRequestData(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Index, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

NTSTATUS NTAPI NtReplyPort(HANDLE PortHandle, PPORT_MESSAGE LpcReply);

NTSTATUS NTAPI NtReplyWaitReceivePort(HANDLE PortHandle, PVOID *PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage);

NTSTATUS NTAPI NtReplyWaitReceivePortEx(HANDLE PortHandle, PVOID *PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage, PLARGE_INTEGER Timeout);

NTSTATUS NTAPI NtReplyWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage);

NTSTATUS NTAPI NtRequestPort(HANDLE PortHandle, PPORT_MESSAGE LpcMessage);

NTSTATUS NTAPI NtRequestWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE LpcReply, PPORT_MESSAGE LpcRequest);

NTSTATUS NTAPI NtSecureConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView, PSID Sid,
                                   PREMOTE_PORT_VIEW ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength);

NTSTATUS NTAPI NtWriteRequestData(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Index, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

//
// Native Calls (NT Executive)
//
NTSTATUS NTAPI NtContinue(PCONTEXT Context, BOOLEAN TestAlert);

NTSTATUS NTAPI NtCallbackReturn(PVOID Result, ULONG ResultLength, NTSTATUS Status);

NTSTATUS NTAPI NtDelayExecution(BOOLEAN Alertable, LARGE_INTEGER *Interval);

NTSTATUS NTAPI NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);

ULONG NTAPI NtGetCurrentProcessorNumber(VOID);

NTSTATUS NTAPI NtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);

NTSTATUS NTAPI NtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context, BOOLEAN SearchFrames);

NTSTATUS NTAPI NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);

NTSTATUS NTAPI NtSetLdtEntries(ULONG Selector1, LDT_ENTRY LdtEntry1, ULONG Selector2, LDT_ENTRY LdtEntry2);

NTSTATUS NTAPI NtStartProfile(HANDLE ProfileHandle);

NTSTATUS NTAPI NtStopProfile(HANDLE ProfileHandle);

NTSTATUS NTAPI NtTestAlert(VOID);

NTSTATUS NTAPI NtYieldExecution(VOID);

NTSTATUS NTAPI NtAddAtom(PWSTR AtomName, ULONG AtomNameLength, PRTL_ATOM Atom);

NTSTATUS NTAPI NtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState);

NTSTATUS NTAPI NtClearEvent(HANDLE EventHandle);

NTSTATUS NTAPI NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);

NTSTATUS NTAPI NtCreateEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtCreateKeyedEvent(PHANDLE OutHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);

NTSTATUS NTAPI NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner);

NTSTATUS NTAPI NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount);

NTSTATUS NTAPI NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType);

NTSTATUS NTAPI NtDeleteAtom(RTL_ATOM Atom);

NTSTATUS NTAPI NtDisplayString(PUNICODE_STRING DisplayString);

NTSTATUS NTAPI NtEnumerateSystemEnvironmentValuesEx(ULONG InformationClass, PVOID Buffer, ULONG BufferLength);

NTSTATUS NTAPI NtFindAtom(PWSTR AtomName, ULONG AtomNameLength, PRTL_ATOM Atom);

NTSTATUS NTAPI NtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtOpenKeyedEvent(PHANDLE OutHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtOpenEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAcces, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtPulseEvent(HANDLE EventHandle, PLONG PulseCount);

NTSTATUS NTAPI NtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass, PVOID EventInformation, ULONG EventInformationLength, PULONG ReturnLength);

NTSTATUS NTAPI NtQueryInformationAtom(RTL_ATOM Atom, ATOM_INFORMATION_CLASS AtomInformationClass, PVOID AtomInformation, ULONG AtomInformationLength, PULONG ReturnLength);

NTSTATUS NTAPI NtQuerySystemEnvironmentValue(PUNICODE_STRING Name, PWSTR Value, ULONG Length, PULONG ReturnLength);

NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ReturnLength, PULONG Attributes);

NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG Length, PULONG ResultLength);

NTSTATUS NTAPI NtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

NTSTATUS NTAPI NtReleaseMutant(HANDLE MutantHandle, PLONG ReleaseCount);

NTSTATUS NTAPI NtReleaseKeyedEvent(HANDLE EventHandle, PVOID Key, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

NTSTATUS NTAPI NtReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount);

NTSTATUS NTAPI NtResetEvent(HANDLE EventHandle, PLONG NumberOfWaitingThreads);

NTSTATUS NTAPI NtSetDefaultHardErrorPort(HANDLE PortHandle);

NTSTATUS NTAPI NtSetEvent(HANDLE EventHandle, PLONG PreviousState);

NTSTATUS NTAPI NtSetEventBoostPriority(HANDLE EventHandle);

NTSTATUS NTAPI NtSetHighEventPair(HANDLE EventPairHandle);

NTSTATUS NTAPI NtSetHighWaitLowEventPair(HANDLE EventPairHandle);

NTSTATUS NTAPI NtSetLowEventPair(HANDLE EventPair);

NTSTATUS NTAPI NtSetLowWaitHighEventPair(HANDLE EventPair);

NTSTATUS NTAPI NtSetSystemEnvironmentValue(PUNICODE_STRING VariableName, PUNICODE_STRING Value);

NTSTATUS NTAPI NtSetSystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid);

NTSTATUS NTAPI NtSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength);

NTSTATUS NTAPI NtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext,
                          BOOLEAN WakeTimer, LONG Period, PBOOLEAN PreviousState);

NTSTATUS NTAPI NtSetUuidSeed(PUCHAR UuidSeed);

NTSTATUS NTAPI NtShutdownSystem(SHUTDOWN_ACTION Action);

NTSTATUS NTAPI NtWaitForKeyedEvent(HANDLE EventHandle, PVOID Key, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

NTSTATUS NTAPI NtWaitHighEventPair(HANDLE EventPairHandle);

NTSTATUS NTAPI NtWaitLowEventPair(HANDLE EventPairHandle);

NTSTATUS NTAPI NtTraceEvent(ULONG TraceHandle, ULONG Flags, ULONG TraceHeaderLength, PEVENT_TRACE_HEADER TraceHeader);

//
// Native Calls (Security Manager)
//
NTSTATUS NTAPI NtAccessCheck(PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken, ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping,
                             PPRIVILEGE_SET PrivilegeSet, PULONG ReturnLength, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus);

NTSTATUS NTAPI NtAccessCheckByType(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE ClientToken, ACCESS_MASK DesiredAccess,
                                   POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeLength, PGENERIC_MAPPING GenericMapping,
                                   PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus);

NTSTATUS NTAPI NtAccessCheckByTypeResultList(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE ClientToken, ACCESS_MASK DesiredAccess,
                                             POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeLength, PGENERIC_MAPPING GenericMapping,
                                             PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus);

NTSTATUS NTAPI NtAccessCheckAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor,
                                          ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus, PBOOLEAN GenerateOnClose);

NTSTATUS NTAPI NtAdjustGroupsToken(HANDLE TokenHandle, BOOLEAN ResetToDefault, PTOKEN_GROUPS NewState, ULONG BufferLength, PTOKEN_GROUPS PreviousState, PULONG ReturnLength);

NTSTATUS NTAPI NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);

NTSTATUS NTAPI NtAllocateLocallyUniqueId(LUID *LocallyUniqueId);

NTSTATUS NTAPI NtAllocateUuids(PULARGE_INTEGER Time, PULONG Range, PULONG Sequence, PUCHAR Seed);

NTSTATUS NTAPI NtCompareTokens(HANDLE FirstTokenHandle, HANDLE SecondTokenHandle, PBOOLEAN Equal);

NTSTATUS NTAPI NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime,
                             PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups, PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner, PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                             PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource);

NTSTATUS NTAPI NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);

NTSTATUS NTAPI NtImpersonateAnonymousToken(HANDLE Thread);

NTSTATUS NTAPI NtOpenObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor,
                                      HANDLE ClientToken, ACCESS_MASK DesiredAccess, ACCESS_MASK GrantedAccess, PPRIVILEGE_SET Privileges, BOOLEAN ObjectCreation, BOOLEAN AccessGranted, PBOOLEAN GenerateOnClose);

NTSTATUS NTAPI NtOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle);

NTSTATUS NTAPI NtPrivilegeCheck(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);

NTSTATUS NTAPI NtPrivilegedServiceAuditAlarm(PUNICODE_STRING SubsystemName, PUNICODE_STRING ServiceName, HANDLE ClientToken, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted);

NTSTATUS NTAPI NtPrivilegeObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE ClientToken, ACCESS_MASK DesiredAccess, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted);

NTSTATUS NTAPI NtQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);

NTSTATUS NTAPI NtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength);

//
// Native Calls (Processes/Threads)
//
NTSTATUS NTAPI NtAlertResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

NTSTATUS NTAPI NtAlertThread(HANDLE ThreadHandle);

NTSTATUS NTAPI NtAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle);

NTSTATUS NTAPI NtCreateJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtCreateJobSet(ULONG NumJob, PJOB_SET_ARRAY UserJobSet, ULONG Flags);

NTSTATUS NTAPI NtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort);

NTSTATUS NTAPI NtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                  HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort,
                  BOOLEAN InJob);

NTSTATUS NTAPI NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
               HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext,
               PINITIAL_TEB UserStack, BOOLEAN CreateSuspended);

NTSTATUS NTAPI NtImpersonateThread(HANDLE ThreadHandle, HANDLE ThreadToImpersonate, PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);

NTSTATUS NTAPI NtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle);

NTSTATUS NTAPI NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

NTSTATUS NTAPI NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);

NTSTATUS NTAPI NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

NTSTATUS NTAPI NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle);

NTSTATUS NTAPI NtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle);

NTSTATUS NTAPI NtQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass, PVOID JobInformation, ULONG JobInformationLength,
                                           PULONG ReturnLength);

#ifndef _NTDDK_
NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength,
                                         PULONG ReturnLength);
#endif

NTSTATUS NTAPI NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength,
                                        PULONG ReturnLength);

NTSTATUS NTAPI NtRegisterThreadTerminatePort(HANDLE TerminationPort);

NTSTATUS NTAPI NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);

NTSTATUS NTAPI NtSetInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass, PVOID JobInformation, ULONG JobInformationLength);

NTSTATUS NTAPI NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

NTSTATUS NTAPI NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);

NTSTATUS NTAPI NtSuspendProcess(HANDLE ProcessHandle);

NTSTATUS NTAPI NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

NTSTATUS NTAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

NTSTATUS NTAPI NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);

NTSTATUS NTAPI NtTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus);

//
// Native calls (Dynamic Loader)
//
NTSTATUS NTAPI LdrGetProcedureAddress(PVOID BaseAddress, PANSI_STRING Name, ULONG Ordinal, PVOID *ProcedureAddress);

NTSTATUS NTAPI LdrEnumerateLoadedModules(BOOLEAN ReservedFlag, PLDR_ENUM_CALLBACK EnumProc, PVOID Context);

NTSTATUS NTAPI LdrLoadDll(PWSTR SearchPath, PULONG LoadFlags, PUNICODE_STRING Name, PVOID *BaseAddress);

NTSTATUS NTAPI LdrQueryProcessModuleInformation(PRTL_PROCESS_MODULES ModuleInformation, ULONG Size, PULONG ReturnedSize);

NTSTATUS NTAPI LdrUnloadDll(PVOID BaseAddress);

//
// Native calls
//
NTSTATUS NTAPI NtAddBootEntry(PBOOT_ENTRY BootEntry, ULONG Id);

NTSTATUS NTAPI NtAddDriverEntry(PEFI_DRIVER_ENTRY BootEntry, ULONG Id);

NTSTATUS NTAPI NtCancelIoFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock);

NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, IO_STATUS_BLOCK *IoStatusBlock,
                            PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                            PVOID EaBuffer, ULONG EaLength);

NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG NumberOfConcurrentThreads);

NTSTATUS NTAPI NtCreateMailslotFile(PHANDLE MailSlotFileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, IO_STATUS_BLOCK *IoStatusBlock,
                                    ULONG FileAttributes, ULONG ShareAccess, ULONG MaxMessageSize, PLARGE_INTEGER TimeOut);

NTSTATUS NTAPI NtCreateNamedPipeFile(PHANDLE NamedPipeFileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, IO_STATUS_BLOCK *IoStatusBlock,
                                     ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, ULONG WriteModeMessage, ULONG ReadModeMessage,
                                     ULONG NonBlocking, ULONG MaxInstances, ULONG InBufferSize, ULONG OutBufferSize, PLARGE_INTEGER DefaultTimeOut);

NTSTATUS NTAPI NtDeleteDriverEntry(ULONG Id);

NTSTATUS NTAPI NtDeleteBootEntry(ULONG Id);

NTSTATUS NTAPI NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK *IoStatusBlock,
                                     ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

NTSTATUS NTAPI NtEnumerateBootEntries(PVOID Buffer, PULONG BufferLength);

NTSTATUS NTAPI NtEnumerateDriverEntries(PVOID Buffer, PULONG BufferLength);

NTSTATUS NTAPI NtFlushBuffersFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock);

NTSTATUS NTAPI NtFlushWriteBuffer(VOID);

NTSTATUS NTAPI NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK *IoStatusBlock,
                               ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);

NTSTATUS NTAPI NtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK *IoStatusBlock,
                          PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediatedly, BOOLEAN ExclusiveLock);

NTSTATUS NTAPI NtModifyBootEntry(PBOOT_ENTRY BootEntry);

NTSTATUS NTAPI NtModifyDriverEntry(PEFI_DRIVER_ENTRY DriverEntry);

NTSTATUS NTAPI NtNotifyChangeDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK *IoStatusBlock,
                                           PVOID Buffer, ULONG BufferSize, ULONG CompletionFilter, BOOLEAN WatchTree);

NTSTATUS NTAPI NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, IO_STATUS_BLOCK *IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

NTSTATUS NTAPI NtOpenIoCompletion(PHANDLE CompetionPort, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,PFILE_BASIC_INFORMATION FileInformation);

NTSTATUS NTAPI NtQueryDriverEntryOrder(PULONG Ids, PULONG Count);

NTSTATUS NTAPI NtQueryBootEntryOrder(PULONG Ids, PULONG Count);

NTSTATUS NTAPI NtQueryBootOptions(PBOOT_OPTIONS BootOptions, PULONG BootOptionsLength);

NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK *IoStatusBlock,
                                    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                    PUNICODE_STRING FileName, BOOLEAN RestartScan);

NTSTATUS NTAPI NtQueryEaFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry,
                             PVOID EaList, ULONG EaListLength, PULONG EaIndex, BOOLEAN RestartScan);

NTSTATUS NTAPI NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation);

NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FileInformation, ULONG Length,
                                      FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS NTAPI NtQueryIoCompletion(HANDLE IoCompletionHandle, IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
                                   PVOID IoCompletionInformation, ULONG IoCompletionInformationLength, PULONG ResultLength);

NTSTATUS NTAPI NtQueryQuotaInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID Buffer, ULONG Length,
                                           BOOLEAN ReturnSingleEntry, PVOID SidList, ULONG SidListLength, PSID StartSid,
                                           BOOLEAN RestartScan);

NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FsInformation, ULONG Length,
                                            FS_INFORMATION_CLASS FsInformationClass);

NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK *IoStatusBlock,
                          PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS NTAPI NtReadFileScatter(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE UserApcRoutine, PVOID UserApcContext, IO_STATUS_BLOCK *UserIoStatusBlock,
                                 FILE_SEGMENT_ELEMENT BufferDescription[], ULONG BufferLength, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE IoCompletionHandle, PVOID *CompletionKey, PVOID *CompletionContext, IO_STATUS_BLOCK *IoStatusBlock, PLARGE_INTEGER Timeout);

NTSTATUS NTAPI NtSetBootEntryOrder(PULONG Ids, PULONG Count);

NTSTATUS NTAPI NtSetBootOptions(PBOOT_OPTIONS BootOptions, ULONG FieldsToChange);

NTSTATUS NTAPI NtSetDriverEntryOrder(PULONG Ids, PULONG Count);

NTSTATUS NTAPI NtSetEaFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID EaBuffer, ULONG EaBufferSize);

NTSTATUS NTAPI NtSetInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FileInformation, ULONG Length,
                                    FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS NTAPI NtSetIoCompletion(HANDLE IoCompletionPortHandle, PVOID CompletionKey, PVOID CompletionContext,
                                 NTSTATUS CompletionStatus, ULONG CompletionInformation);

NTSTATUS NTAPI NtSetQuotaInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID Buffer, ULONG BufferLength);

NTSTATUS NTAPI NtSetVolumeInformationFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FsInformation, ULONG Length,
                                          FS_INFORMATION_CLASS FsInformationClass);

NTSTATUS NTAPI NtTranslateFilePath(PFILE_PATH InputFilePath, ULONG OutputType, PFILE_PATH OutputFilePath, ULONG OutputFilePathLength);

NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);

NTSTATUS NTAPI NtUnlockFile(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, ULONG Key);

NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK * IoStatusBlock,
                           PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS NTAPI NtWriteFileGather(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK * IoStatusBlock,
                                 FILE_SEGMENT_ELEMENT BufferDescription[], ULONG BufferLength, PLARGE_INTEGER ByteOffset, PULONG Key);
//
// Thread Environment Block (TEB) defines and access functions.
typedef struct __TEB {
  NT_TIB Tib;
  VOID  *EnvironmentPointer;
  CLIENT_ID Cid;
  VOID *ActiveRpcInfo;
  VOID *ThreadLocalStoragePointer;
  PEB *ProcessEnvironmentBlock;
  unsigned int LastStatusValue;
  BYTE Reserved1[1844];
  PVOID Reserved2[412];
  PVOID TlsSlots[64];
  BYTE Reserved3[8];
  PVOID Reserved4[26];
  PVOID ReservedForOle;
  PVOID Reserved5[4];
  PVOID *TlsExpansionSlots;
} _TEB;
#define NtCurrentPeb() (((_TEB*)NtCurrentTeb())->ProcessEnvironmentBlock)

//
// List Functions
//
FORCEINLINE
VOID
InitializeListHead(PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

FORCEINLINE
VOID
InsertHeadList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldFlink;
    OldFlink = ListHead->Flink;
    Entry->Flink = OldFlink;
    Entry->Blink = ListHead;
    OldFlink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE
VOID
InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldBlink;
    OldBlink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = OldBlink;
    OldBlink->Flink = Entry;
    ListHead->Blink = Entry;
}

FORCEINLINE
BOOLEAN
IsListEmpty(const LIST_ENTRY * ListHead)
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
PSINGLE_LIST_ENTRY
PopEntryList(PSINGLE_LIST_ENTRY ListHead)
{
    PSINGLE_LIST_ENTRY FirstEntry;
    FirstEntry = ListHead->Next;
    if (FirstEntry != NULL) {
        ListHead->Next = FirstEntry->Next;
    }
    return FirstEntry;
}

FORCEINLINE
VOID
PushEntryList(PSINGLE_LIST_ENTRY ListHead, PSINGLE_LIST_ENTRY Entry)
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

FORCEINLINE
BOOLEAN
RemoveEntryList(PLIST_ENTRY Entry)
{
    PLIST_ENTRY OldFlink;
    PLIST_ENTRY OldBlink;

    OldFlink = Entry->Flink;
    OldBlink = Entry->Blink;
    OldFlink->Blink = OldBlink;
    OldBlink->Flink = OldFlink;
    return (BOOLEAN)(OldFlink == OldBlink);
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
PLIST_ENTRY
RemoveTailList(PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}

//
// Critical Section/Resource Functions
//
NTSTATUS
NTAPI
RtlDeleteCriticalSection (RTL_CRITICAL_SECTION *CriticalSection);

NTSTATUS
NTAPI
RtlEnterCriticalSection(RTL_CRITICAL_SECTION *CriticalSection);

NTSTATUS
NTAPI
RtlInitializeCriticalSection(RTL_CRITICAL_SECTION *CriticalSection);

NTSTATUS
NTAPI
RtlInitializeCriticalSectionAndSpinCount(RTL_CRITICAL_SECTION *CriticalSection, ULONG SpinCount);

NTSTATUS
NTAPI
RtlLeaveCriticalSection(RTL_CRITICAL_SECTION *CriticalSection);

BOOLEAN
NTAPI
RtlTryEnterCriticalSection(RTL_CRITICAL_SECTION *CriticalSection);

//
// Heap Functions
//
#define RtlGetProcessHeap() (NtCurrentPeb()->ProcessHeap)

PVOID NTAPI
RtlAllocateHeap(VOID *HeapHandle, ULONG Flags, SIZE_T Size);

PVOID NTAPI
RtlCreateHeap(ULONG Flags, VOID *BaseAddress, SIZE_T SizeToReserve,
              SIZE_T SizeToCommit, VOID *Lock,
              RTL_HEAP_PARAMETERS *Parameters);

HANDLE NTAPI
RtlDestroyHeap(HANDLE Heap);

ULONG NTAPI
RtlExtendHeap(HANDLE Heap, ULONG Flags, VOID *P, SIZE_T Size);

BOOLEAN NTAPI
RtlFreeHeap(HANDLE HeapHandle, ULONG Flags, VOID *P);

PVOID NTAPI
RtlReAllocateHeap(HANDLE Heap, ULONG Flags, VOID *Ptr, SIZE_T Size);

SIZE_T NTAPI
RtlSizeHeap(VOID *HeapHandle, ULONG Flags, VOID *MemoryPointer);

//
// CRC Functions
//
ULONG NTAPI
RtlComputeCrc32(ULONG InitialCrc, UCHAR *Buffer, ULONG Length);

//
// Single-Character Functions
//
NTSTATUS
NTAPI
RtlIntegerToChar(ULONG Value, ULONG Base, ULONG Length, PCHAR String);

NTSTATUS
NTAPI
RtlCharToInteger(PCSZ String, ULONG Base, PULONG Value);

NTSTATUS
NTAPI
RtlIntegerToUnicode(ULONG Value, ULONG Base, ULONG Length, LPWSTR String);

//
// Unicode String Functions
//
FORCEINLINE
VOID
RtlInitEmptyUnicodeString(PUNICODE_STRING UnicodeString, PWCHAR Buffer, USHORT BufferSize)
{
    UnicodeString->Length = 0;
    UnicodeString->MaximumLength = BufferSize;
    UnicodeString->Buffer = Buffer;
}

FORCEINLINE
VOID
RtlInitEmptyAnsiString(PANSI_STRING AnsiString, PCHAR Buffer, USHORT BufferSize)
{
    AnsiString->Length = 0;
    AnsiString->MaximumLength = BufferSize;
    AnsiString->Buffer = Buffer;
}

NTSTATUS
NTAPI
RtlAppendUnicodeToString(PUNICODE_STRING Destination, PCWSTR Source);

NTSTATUS
NTAPI
RtlAppendUnicodeStringToString(PUNICODE_STRING Destination, PCUNICODE_STRING Source);

VOID
NTAPI
RtlCopyUnicodeString(PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString);

LONG
NTAPI
RtlCompareUnicodeString(PCUNICODE_STRING String1, PCUNICODE_STRING String2,
                        BOOLEAN CaseInsensitive);

BOOLEAN
NTAPI
RtlEqualUnicodeString(PCUNICODE_STRING String1, PCUNICODE_STRING String2,
                      BOOLEAN CaseInsensitive);

BOOLEAN
NTAPI
RtlPrefixUnicodeString(PCUNICODE_STRING String1, PCUNICODE_STRING String2,
                       BOOLEAN CaseInsensitive);

VOID
NTAPI
RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

VOID
NTAPI
RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);

BOOLEAN
NTAPI
RtlCreateUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

NTSTATUS
NTAPI
RtlIntegerToUnicodeString(ULONG Value, ULONG Base, PUNICODE_STRING String);

NTSTATUS
NTAPI
RtlUnicodeStringToInteger(PCUNICODE_STRING String, ULONG Base, PULONG Value);

//
// ANSI<->Unicode String Conversion functions
//
VOID
NTAPI
RtlInitAnsiString(PANSI_STRING DestinationString, PCSZ SourceString);

VOID
NTAPI
RtlFreeAnsiString(PANSI_STRING AnsiString);

NTSTATUS
NTAPI
RtlUnicodeStringToAnsiString(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString,
                             BOOLEAN AllocateDestinationString);

NTSTATUS
NTAPI
RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString,
                             BOOLEAN AllocateDestinationString);

//
// Time-related functions
//
VOID
NTAPI
RtlTimeToTimeFields(PLARGE_INTEGER Time, PTIME_FIELDS TimeFields);

BOOLEAN NTAPI
RtlTimeFieldsToTime(TIME_FIELDS *TimeFields, LARGE_INTEGER *Time);

//
// Path-related functions
//

BOOLEAN
NTAPI
RtlDosPathNameToNtPathName_U(PCWSTR DosPathName, PUNICODE_STRING NtPathName,
                             PCWSTR *NtFileNamePart, PRTL_RELATIVE_NAME_U DirectoryInfo);
ULONG
NTAPI
RtlDosSearchPath_U(PCWSTR Path, PCWSTR FileName, PCWSTR Extension,
                   ULONG BufferSize, PWSTR Buffer, PWSTR *PartName);

//
// Environment-related functions
//
NTSTATUS
NTAPI
RtlCreateEnvironment(BOOLEAN Inherit, PWSTR *Environment);

VOID
NTAPI
RtlDestroyEnvironment(PWSTR Environment);

NTSTATUS
NTAPI
RtlQueryEnvironmentVariable_U(PWSTR Environment, PUNICODE_STRING Name,
                              PUNICODE_STRING Value);

NTSTATUS
NTAPI
RtlSetEnvironmentVariable(PWSTR *Environment, PUNICODE_STRING Name,
                          PUNICODE_STRING Value);

NTSTATUS
NTAPI
RtlExpandEnvironmentStrings_U(PWSTR Environment, PUNICODE_STRING Source,
                              PUNICODE_STRING Destination, PULONG Length);

//
// Process Parameter Block Initialization functions
//

NTSTATUS
NTAPI
RtlCreateProcessParameters (PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
                            UNICODE_STRING *ImagePathName, UNICODE_STRING *DllPath,
                            UNICODE_STRING *CurrentDirectory, UNICODE_STRING *CommandLine,
                            PWSTR Environment, UNICODE_STRING *WindowTitle, UNICODE_STRING *DesktopInfo,
                            UNICODE_STRING *ShellInfo, UNICODE_STRING *RuntimeInfo);

PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlDeNormalizeProcessParams(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

NTSTATUS
NTAPI
RtlDestroyProcessParameters(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlNormalizeProcessParams(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

//
// Process Parameter Block field accessor functions
//
static inline void RtlGetCommandLine(UNICODE_STRING *wcmdln)
{
    UNICODE_STRING *cmdline = &(NtCurrentPeb()->ProcessParameters->CommandLine);
    wcmdln->Buffer = cmdline->Buffer;
    wcmdln->Buffer[cmdline->Length] = L'\0';
    wcmdln->Length = cmdline->Length;
    wcmdln->MaximumLength = cmdline->MaximumLength;
}

static inline HANDLE RtlGetConsoleHandle(void)
{
    return (NtCurrentPeb()->ProcessParameters->hStdError);
}

static inline void RtlGetCwdByName(UNICODE_STRING *cwd)
{
    UNICODE_STRING *_cwd = &(NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath);
    cwd->Buffer = _cwd->Buffer;
    cwd->Buffer[_cwd->Length] = L'\0';
    cwd->Length = _cwd->Length;
    cwd->MaximumLength = _cwd->MaximumLength;
}

static inline HANDLE RtlGetCwdByHandle(void)
{
    return (NtCurrentPeb()->ProcessParameters->CurrentDirectory.Handle);
}

//
// NT Loader functions
//
NTSTATUS
NTAPI
LdrQueryImageFileExecutionOptions(PUNICODE_STRING SubKey,
                                  PCWSTR ValueName, ULONG ValueSize,
                                  PVOID Buffer, ULONG BufferSize,
                                  PULONG RetunedLength);

typedef VOID (NTAPI *PLDR_CALLBACK)(PVOID CallbackContext, PCHAR Name);
NTSTATUS
NTAPI
LdrVerifyImageMatchesChecksum(HANDLE FileHandle, PLDR_CALLBACK Callback, PVOID CallbackContext,
                              USHORT *ImageCharacteristics);

//
// Debug Functions
//
VOID NTAPI
DbgBreakPointWithStatus(ULONG Status);

NTSTATUS NTAPI
DbgUiConnectToDbg(VOID);

NTSTATUS NTAPI
DbgUiContinue(CLIENT_ID *ClientId, ULONG ContinueStatus);

NTSTATUS NTAPI
DbgUiDebugActiveProcess(HANDLE Process);

NTSTATUS NTAPI
DbgUiStopDebugging(HANDLE Process);

NTSTATUS NTAPI
DbgUiWaitStateChange(PDBGUI_WAIT_STATE_CHANGE DbgUiWaitStateCange, PLARGE_INTEGER TimeOut);

VOID NTAPI
DbgUiRemoteBreakin(VOID);

NTSTATUS NTAPI
DbgUiIssueRemoteBreakin(HANDLE Process);

HANDLE NTAPI
DbgUiGetThreadDebugObject(VOID);

//
// LUID Macros
//
#define RtlEqualLuid(L1, L2) (((L1)->HighPart == (L2)->HighPart) && \
                              ((L1)->LowPart  == (L2)->LowPart))
FORCEINLINE
LUID
RtlConvertUlongToLuid(ULONG Ulong)
{
    LUID TempLuid;

    TempLuid.LowPart = Ulong;
    TempLuid.HighPart = 0;
    return TempLuid;
}

//
// Security Functions
//
NTSTATUS
NTAPI
RtlAbsoluteToSelfRelativeSD(PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
                            PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
                            PULONG BufferLength);

NTSTATUS
NTAPI
RtlAddAccessAllowedAce(PACL Acl, ULONG Revision, ACCESS_MASK AccessMask, PSID Sid);

NTSTATUS
NTAPI
RtlAddAccessDeniedAce(PACL Acl, ULONG Revision, ACCESS_MASK AccessMask, PSID Sid);

NTSTATUS
NTAPI
RtlAddAuditAccessAce(PACL Acl, ULONG Revision, ACCESS_MASK AccessMask, PSID Sid,
                     BOOLEAN Success, BOOLEAN Failure);

NTSTATUS
NTAPI
RtlAdjustPrivilege(ULONG Privilege, BOOLEAN NewValue, BOOLEAN ForThread,
                   PBOOLEAN OldValue);

NTSTATUS
NTAPI
RtlAllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY IdentifierAuthority, UCHAR SubAuthCount,
                            ULONG SubAuth0, ULONG SubAuth1, ULONG SubAuth2, ULONG SubAuth3,
                            ULONG SubAuth4, ULONG SubAuth5, ULONG SubAuth6, ULONG SubAuth7,
                            PSID *Sid);

VOID
NTAPI
RtlCopyLuid(PLUID DestinationLuid, PLUID SourceLuid);

VOID
NTAPI
RtlCopyLuidAndAttributesArray(ULONG Count, PLUID_AND_ATTRIBUTES Src, PLUID_AND_ATTRIBUTES Dest);

NTSTATUS
NTAPI
RtlCopySid(ULONG DestinationSidLength, PSID DestinationSid, PSID SourceSid);

NTSTATUS
NTAPI
RtlCreateAcl(PACL Acl, ULONG AclSize, ULONG AclRevision);

NTSTATUS
NTAPI
RtlCreateSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Revision);

BOOLEAN
NTAPI
RtlEqualSid (PSID Sid1, PSID Sid2);

PVOID
NTAPI
RtlFreeSid(PSID Sid);

NTSTATUS
NTAPI
RtlGetAce(PACL Acl, ULONG AceIndex, PVOID *Ace);

PSID_IDENTIFIER_AUTHORITY
NTAPI
RtlIdentifierAuthoritySid(PSID Sid);

NTSTATUS
NTAPI
RtlInitializeSid(PSID Sid, PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
                 UCHAR SubAuthorityCount);

ULONG
NTAPI
RtlLengthRequiredSid(IN ULONG SubAuthorityCount);

ULONG
NTAPI
RtlLengthSid(IN PSID Sid);

VOID
NTAPI
RtlMapGenericMask(PACCESS_MASK AccessMask, PGENERIC_MAPPING GenericMapping);

NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN DaclPresent,
                             PACL Dacl, BOOLEAN DaclDefaulted);

NTSTATUS
NTAPI
RtlSetGroupSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID Group,
                              BOOLEAN GroupDefaulted);

NTSTATUS
NTAPI
RtlSetOwnerSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID Owner,
                              BOOLEAN OwnerDefaulted);

NTSTATUS
NTAPI
RtlSetSaclSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN SaclPresent,
                             PACL Sacl, BOOLEAN SaclDefaulted);

PUCHAR
NTAPI
RtlSubAuthorityCountSid(PSID Sid);

PULONG
NTAPI
RtlSubAuthoritySid(PSID Sid, ULONG SubAuthority);

BOOLEAN
NTAPI
RtlValidRelativeSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptorInput,
                                   ULONG SecurityDescriptorLength,
                                   SECURITY_INFORMATION RequiredInformation);

BOOLEAN
NTAPI
RtlValidSecurityDescriptor(IN PSECURITY_DESCRIPTOR SecurityDescriptor);

BOOLEAN
NTAPI
RtlValidSid(IN PSID Sid);

BOOLEAN
NTAPI
RtlValidAcl(PACL Acl);

//
// Boot Status Data Functions
//
NTSTATUS
NTAPI
RtlCreateBootStatusDataFile(VOID);

NTSTATUS
NTAPI
RtlGetSetBootStatusData(HANDLE FileHandle, BOOLEAN WriteMode, RTL_BSD_ITEM_TYPE DataClass,
                        PVOID Buffer, ULONG BufferSize, PULONG ReturnLength);

NTSTATUS
NTAPI
RtlLockBootStatusData(PHANDLE FileHandle);

NTSTATUS
NTAPI
RtlUnlockBootStatusData(HANDLE FileHandle);

//
// Registry convenience functions
//
typedef NTSTATUS
(NTAPI *PRTL_QUERY_REGISTRY_ROUTINE)(IN PWSTR ValueName, IN ULONG ValueType,
                                     IN PVOID ValueData, IN ULONG ValueLength,
                                     IN PVOID Context, IN PVOID EntryContext);

typedef struct _RTL_QUERY_REGISTRY_TABLE
{
    PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
    ULONG Flags;
    PCWSTR Name;
    PVOID EntryContext;
    ULONG DefaultType;
    PVOID DefaultData;
    ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

NTSTATUS
NTAPI
RtlQueryRegistryValues(ULONG RelativeTo, PCWSTR Path, PRTL_QUERY_REGISTRY_TABLE QueryTable,
                       PVOID Context, PVOID Environment);

#endif
