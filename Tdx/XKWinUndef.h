
#ifndef _XKERNEL_COMMON_HEAD_DEFINE_
#define _XKERNEL_COMMON_HEAD_DEFINE_

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _SSDT_Entry
{
	unsigned int*	ServiceDispatchTableBase;
	unsigned int*	ServiceCounterTableBase;
	unsigned int	NumberOfServices;
	unsigned char*	ServiceParameterTableBase;
}SSDT_Entry;

__declspec(dllimport) SSDT_Entry KeServiceDescriptorTable;
__declspec(dllimport) _stdcall KeAddSystemServiceTable(PVOID, PVOID, PVOID, PVOID, PVOID);

#define SystemService(sysCall) \
	KeServiceDescriptorTable.ServiceDispatchTableBase[*(PULONG)((PUCHAR)sysCall+1)]

#define SystemServiceByNo(sysCallNo) \
	KeServiceDescriptorTable.ServiceDispatchTableBase[sysCallNo]


// 2. SSDT Define
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation, 				// 0 
	SystemProcessorInformation, 			// 1 
	SystemPerformanceInformation, 			// 2
	SystemTimeOfDayInformation, 			// 3
	SystemNotImplemented1, 				    // 4
	SystemProcessesAndThreadsInformation, 	// 5
	SystemCallCounts, 					    // 6
	SystemConfigurationInformation, 		// 7
	SystemProcessorTimes, 				    // 8
	SystemGlobalFlag, 					    // 9
	SystemNotImplemented2, 				    // 10
	SystemModuleInformation, 				// 11 
	SystemLockInformation, 				    // 12
	SystemNotImplemented3, 				    // 13
	SystemNotImplemented4, 				    // 14
	SystemNotImplemented5, 				    // 15
	SystemHandleInformation, 				// 16
	SystemObjectInformation, 				// 17
	SystemPagefileInformation, 				// 18
	SystemInstructionEmulationCounts, 		// 19
	SystemInvalidInfoClass1, 				// 20
	SystemCacheInformation, 				// 21
	SystemPoolTagInformation, 				// 22
	SystemProcessorStatistics, 				// 23
	SystemDpcInformation, 				    // 24
	SystemNotImplemented6, 				    // 25
	SystemLoadImage, 					    // 26
	SystemUnloadImage, 				        // 27
	SystemTimeAdjustment, 				    // 28
	SystemNotImplemented7, 				    // 29
	SystemNotImplemented8, 				    // 30
	SystemNotImplemented9, 				    // 31
	SystemCrashDumpInformation, 			// 32
	SystemExceptionInformation, 			// 33
	SystemCrashDumpStateInformation, 		// 34
	SystemKernelDebuggerInformation, 		// 35
	SystemContextSwitchInformation, 		// 36
	SystemRegistryQuotaInformation, 		// 37
	SystemLoadAndCallImage, 				// 38
	SystemPrioritySeparation, 				// 39
	SystemNotImplemented10, 				// 40
	SystemNotImplemented11, 				// 41
	SystemInvalidInfoClass2, 				// 42
	SystemInvalidInfoClass3, 				// 43
	SystemTimeZoneInformation, 				// 44
	SystemLookasideInformation, 			// 45
	SystemSetTimeSlipEvent, 				// 46
	SystemCreateSession, 				    // 47
	SystemDeleteSession, 				    // 48
	SystemInvalidInfoClass4, 				// 49
	SystemRangeStartInformation, 			// 50
	SystemVerifierInformation, 				// 51
	SystemAddVerifier, 				        // 52
	SystemSessionProcessesInformation 		// 53		
}SYSTEM_INFORMATION_CLASS;                      //内核模块类型，我们要列举的是SystemProcessesAndThreadsInformation,进程和线程信

NTKERNELAPI HANDLE PsGetThreadProcessId(__in PETHREAD Thread);
NTKERNELAPI HANDLE PsGetThreadId(__in PETHREAD Thread);
NTKERNELAPI HANDLE PsGetThreadSessionId(__in PETHREAD Thread);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation (IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG Length, OUT PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess (IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, 
												   OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);


NTKERNELAPI NTSTATUS ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectName,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	IN POBJECT_TYPE ObjectType,
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext OPTIONAL,
	OUT PVOID *Object
	);
extern POBJECT_TYPE *IoDriverObjectType;

#ifdef __cplusplus
}
#endif

#endif
