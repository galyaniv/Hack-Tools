#include <windows.h>
#include <iostream>

using namespace std;
#define FUNCTION_TO_HOOK "MessageBoxW" 


int NewFunc() {
	return MessageBox(NULL, L"Hooked", L"Hooked", NULL);
}

int IATHookFunc() {
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)imageBase + pImageDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = &pImageNtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY importDirectory = &pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONGLONG)imageBase + importDirectory->VirtualAddress);
	while (importDescriptor != NULL)
	{
		PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((ULONGLONG)imageBase + importDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((ULONGLONG)imageBase + importDescriptor->FirstThunk);
		PIMAGE_IMPORT_BY_NAME pImportFunc = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)imageBase + pOriginalFirstThunk->u1.AddressOfData);
		while (pOriginalFirstThunk != NULL && pFirstThunk != NULL)
		{
			if (!strcmp(FUNCTION_TO_HOOK, pImportFunc->Name)) {
				DWORD oldProtection;
				ULONGLONG *pFuncAddress = &pFirstThunk->u1.Function;
				VirtualProtect(pFuncAddress, 8, PAGE_READWRITE, &oldProtection);
				pFirstThunk->u1.Function = (ULONGLONG)&NewFunc;
				VirtualProtect(pFuncAddress, 8, oldProtection, NULL);
				return 1;
			}
			else {
				pOriginalFirstThunk++;
				pFirstThunk++;
				pImportFunc = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)imageBase + pOriginalFirstThunk->u1.AddressOfData);
			}
		}
		importDescriptor ++;
	}
	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		IATHookFunc();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

