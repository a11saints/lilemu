#pragma once
#include <windows.h>
#include <cstdint> 

constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH = static_cast<NTSTATUS>(0xC0000004L);
constexpr NTSTATUS STATUS_SUCCESS = static_cast<NTSTATUS>(0x00000000L);
constexpr ULONG    DUPLICATE_SAME_ATTRIBUTES = 0x00000004u;
inline constexpr bool NT_SUCCESS(NTSTATUS status) {
	return status >= 0;
}


using KPRIORITY = LONG;


enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
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
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformation2,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation

} ;
using SYSTEM_INFORMATION_CLASS = _SYSTEM_INFORMATION_CLASS;


 struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
};
using IO_STATUS_BLOCK = _IO_STATUS_BLOCK;
using PIO_STATUS_BLOCK = _IO_STATUS_BLOCK*;


 struct _FILE_NAME_INFORMATION { // Information Classes 9 and 21
	ULONG FileNameLength;
	WCHAR FileName[1];
};
using FILE_NAME_INFORMATION = _FILE_NAME_INFORMATION;


enum _FILE_INFORMATION_CLASS {
	FileNameInformation = 9,
};
using FILE_INFORMATION_CLASS = _FILE_INFORMATION_CLASS;
using PFILE_INFORMATION_CLASS = _FILE_INFORMATION_CLASS*;


 struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
};
 using UNICODE_STRING = _UNICODE_STRING;
 using PUNICODE_STRING = _UNICODE_STRING*;


struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
 using CLIENT_ID = _CLIENT_ID;
 using PCLIENT_ID = _CLIENT_ID*;


struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
};
using OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES;
using POBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES*;


inline void InitializeObjectAttributes(OBJECT_ATTRIBUTES* p,
	PUNICODE_STRING    n,
	ULONG               a,
	HANDLE              r,
	PSECURITY_DESCRIPTOR s
) noexcept {
	p->Length = sizeof(OBJECT_ATTRIBUTES);
	p->ObjectName = n;
	p->Attributes = a;
	p->RootDirectory = r;
	p->SecurityDescriptor = s;
	p->SecurityQualityOfService = nullptr;
}


struct _MEMORY_REGION_INFORMATION
{
	PVOID AllocationBase; //Imagebase
	ULONG AllocationProtect;
	ULONG RegionType;
	SIZE_T RegionSize; //Size of image
} MEMORY_REGION_INFORMATION, * PMEMORY_REGION_INFORMATION;
using MEMORY_REGION_INFORMATION = _MEMORY_REGION_INFORMATION;
using PMEMORY_REGION_INFORMATION = _MEMORY_REGION_INFORMATION*;

enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} ;
using OBJECT_INFORMATION_CLASS = _OBJECT_INFORMATION_CLASS;
using POBJECT_INFORMATION_CLASS = _OBJECT_INFORMATION_CLASS*;

enum _THREADINFOCLASS {
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
	MaxThreadInfoClass
};
using THREADINFOCLASS = _THREADINFOCLASS;
using PTHREADINFOCLASS = _THREADINFOCLASS*;


enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation, //MemorySectionName, UNICODE_STRING, Wrapper: GetMappedFileNameW
	MemoryRegionInformation, //MemoryBasicVlmInformation, MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation
} ;
using MEMORY_INFORMATION_CLASS = _MEMORY_INFORMATION_CLASS;


enum _PROCESSINFOCLASS {
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
	ProcessResourceManagement,
	ProcessCookie,
	ProcessImageInformation,
	MaxProcessInfoClass
} ;
using _PROCESSINFOCLASS = _PROCESSINFOCLASS;

struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
};
using PEB_LDR_DATA = _PEB_LDR_DATA;
using PPEB_LDR_DATA = _PEB_LDR_DATA*;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} ;

using RTL_USER_PROCESS_PARAMETERS = _RTL_USER_PROCESS_PARAMETERS;
using PRTL_USER_PROCESS_PARAMETERS = _RTL_USER_PROCESS_PARAMETERS*;


typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PVOID						  PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _MEMORY_WORKING_SET_LIST
{
	ULONG	NumberOfPages;
	ULONG	WorkingSetList[1];
} MEMORY_WORKING_SET_LIST, * PMEMORY_WORKING_SET_LIST;

typedef struct _MEMORY_SECTION_NAME
{
	UNICODE_STRING	SectionFileName;
} MEMORY_SECTION_NAME, * PMEMORY_SECTION_NAME;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
	ULONG SessionId;
	ULONG SizeOfBuf;
	PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

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
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress; /* This is only filled in on Vista and above */
	ULONG_PTR Reserved2;
	ULONG_PTR Reserved3;
	ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
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
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


///////////////////////////////////////////////////////////////////////////////////////
//Evolution of Process Environment Block (PEB) http://blog.rewolf.pl/blog/?p=573
//March 2, 2013 / ReWolf posted in programming, reverse engineering, source code, x64 /

#pragma pack(push)
#pragma pack(1)

template <class T>
struct LIST_ENTRY_T {
	T Flink;
	T Blink;
};

template <class T>
struct UNICODE_STRING_T {
	union {
		struct {
			WORD Length;
			WORD MaximumLength;
		};
		T dummy;
	};
	T _Buffer;
};

template <class T, class NGF, int A>
struct _PEB_T {
	union {
		struct {
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE _SYSTEM_DEPENDENT_01;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T _SYSTEM_DEPENDENT_02;
	T _SYSTEM_DEPENDENT_03;
	T _SYSTEM_DEPENDENT_04;
	union {
		T KernelCallbackTable;
		T UserSharedInfoPtr;
	};
	DWORD SystemReserved;
	DWORD _SYSTEM_DEPENDENT_05;
	T _SYSTEM_DEPENDENT_06;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T _SYSTEM_DEPENDENT_07;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union {
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
};
using PEB32 = _PEB_T<DWORD, DWORD64, 34>;
using PEB64 = _PEB_T<DWORD64, DWORD, 30>;
using PEB_CURRENT = PEB64 ;

#pragma pack(pop)

using uNtTerminateProcess =
NTSTATUS(WINAPI*)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

using uNtQueryObject =
NTSTATUS(WINAPI*)(HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength);

using uNtDuplicateObject =
NTSTATUS(WINAPI*)(HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	BOOLEAN InheritHandle,
	ULONG Options);

using uNtQueryInformationFile =
NTSTATUS(WINAPI*)(HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass);

using uNtQueryInformationThread =
NTSTATUS(WINAPI*)(HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength);

using uNtQueryInformationProcess =
NTSTATUS(WINAPI*)(HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

using uNtQuerySystemInformation =
NTSTATUS(WINAPI*)(SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

using uNtQueryVirtualMemory =
NTSTATUS(WINAPI*)(HANDLE ProcessHandle,
	PVOID BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID Buffer,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength);

using uNtOpenProcess =
NTSTATUS(WINAPI*)(PHANDLE ProcessHandle,
	ACCESS_MASK AccessMask,
	PVOID ObjectAttributes,
	PCLIENT_ID ClientId);

using uNtOpenThread =
NTSTATUS(WINAPI*)(PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId);

using uNtResumeThread =
NTSTATUS(WINAPI*)(HANDLE ThreadHandle,
	PULONG SuspendCount);

using uNtSetInformationThread =
NTSTATUS(WINAPI*)(HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength);

using uNtCreateThreadEx =
NTSTATUS(WINAPI*)(PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	int CreateFlags,
	ULONG StackZeroBits,
	LPVOID SizeOfStackCommit,
	LPVOID SizeOfStackReserve,
	LPVOID lpBytesBuffer);

using uNtSuspendProcess = NTSTATUS(WINAPI*)(HANDLE ProcessHandle);

using uNtResumeProcess = NTSTATUS(WINAPI*)(HANDLE ProcessHandle);

using uNtOpenSymbolicLinkObject = NTSTATUS(WINAPI*)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

using uNtQuerySymbolicLinkObject = NTSTATUS(WINAPI*)(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength);

using uRtlNtStatusToDosError = ULONG(WINAPI*)(NTSTATUS Status);

using uNtClose = NTSTATUS(WINAPI*)(HANDLE Handle);

constexpr uint32_t NtCreateThreadExFlagCreateSuspended = 0x1;

constexpr uint32_t NtCreateThreadExFlagSuppressDllMains = 0x2;

constexpr uint32_t NtCreateThreadExFlagHideFromDebugger = 0x4;

constexpr uint32_t SYMBOLIC_LINK_QUERY = 0x0001;

class C_KernelWrapper {
public:
	C_KernelWrapper();
	static uNtCreateThreadEx NtCreateThreadEx;
	static uNtDuplicateObject NtDuplicateObject;
	static uNtOpenProcess NtOpenProcess;
	static uNtOpenThread NtOpenThread;
	static uNtQueryObject NtQueryObject;
	static uNtQueryInformationFile NtQueryInformationFile;
	static uNtQueryInformationProcess NtQueryInformationProcess;
	static uNtQueryInformationThread NtQueryInformationThread;
	static uNtQuerySystemInformation NtQuerySystemInformation;
	static uNtQueryVirtualMemory NtQueryVirtualMemory;
	static uNtResumeProcess NtResumeProcess;
	static uNtResumeThread NtResumeThread;
	static uNtSetInformationThread NtSetInformationThread;
	static uNtSuspendProcess NtSuspendProcess;
	static uNtTerminateProcess NtTerminateProcess;
	static uNtOpenSymbolicLinkObject NtOpenSymbolicLinkObject;
	static uNtQuerySymbolicLinkObject NtQuerySymbolicLinkObject;
	static uNtClose NtClose;
	static uRtlNtStatusToDosError RtlNtStatusToDosError;
	static void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PWSTR SourceString)	{
		DestinationString->Buffer = SourceString;
		DestinationString->MaximumLength = DestinationString->Length = static_cast<USHORT>( wcslen(SourceString)) * sizeof(WCHAR);
	}
};