#pragma once
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>

typedef enum _QUEUE_USER_APC_FLAGS {
	QueueUserApcFlagsNone,
	QueueUserApcFlagsSpecialUserApc,
	QueueUserApcFlagsMaxValue
} QUEUE_USER_APC_FLAGS;

typedef union _USER_APC_OPTION {
	ULONG_PTR UserApcFlags;
	HANDLE MemoryReserveHandle;
} USER_APC_OPTION, * PUSER_APC_OPTION;

typedef VOID(WINAPI *PPS_APC_ROUTINE)(
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	PVOID SystemArgument3,
	PCONTEXT ContextRecord
	);

typedef NTSTATUS (WINAPI* _NtQueueApcThreadEx)(
	IN HANDLE ThreadHandle,
	IN USER_APC_OPTION UserApcOption,
	IN PPS_APC_ROUTINE ApcRoutine,
	IN PVOID SystemArgument1 OPTIONAL,
	IN PVOID SystemArgument2 OPTIONAL,
	IN PVOID SystemArgument3 OPTIONAL
);

