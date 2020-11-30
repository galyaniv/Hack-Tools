// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL DllMainCalled = FALSE;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	DllMainCalled = TRUE;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

extern "C" __declspec(dllexport) void MainEntry() {
	if (DllMainCalled)
	{

		char Module[MAX_PATH + 1];
		GetModuleFileNameA(0, Module, sizeof(Module));
		MessageBoxA(0, Module, "DllMain called!", 0);


	}
	else {
		MessageBoxA(0, "DllMain was not called", NULL, 0);
	}
}