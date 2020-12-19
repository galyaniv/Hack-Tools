#pragma once
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>

namespace Helper
{
	void GetDebugPrivs();
	PVOID GetImageBase();
	PBYTE GetDllVirtualAddress(PBYTE module_base, PDWORD module_size);
	DWORD CreateDllFile(char dllPath[MAX_PATH]);
	DWORD FindPID();
	void InjectDll(HANDLE hProcess, char szDllPath[]);
	

}