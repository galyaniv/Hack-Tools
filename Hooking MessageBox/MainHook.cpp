#include "MainHook.h"

char old[6] = { 0 };
PVOID memCreateMassege = NULL;
DWORD bytesWriten = 0;

int WINAPI runCalc(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	char calc[] = "calc.exe";
	STARTUPINFOA si = { sizeof(si) };;
	PROCESS_INFORMATION pi;
	if (CreateProcessA(NULL, calc, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	WriteProcessMemory(GetCurrentProcess(), memCreateMassege, old, sizeof(old), &bytesWriten);
	return MessageBoxA(NULL, lpText, lpCaption, uType);
}

int main() {
	void *runCalcHook = &runCalc;
	HINSTANCE library = LoadLibraryA("user32.dll");
	memCreateMassege = GetProcAddress(library, "MessageBoxA");
	memcpy(&old, memCreateMassege, 6);
	char hook[6] = {0};
	memcpy_s(hook, 1, "\x68", 1);
	memcpy_s(hook + 1, 4, &runCalcHook, 4);
	memcpy_s(hook + 5, 1, "\xC3", 1);

	WriteProcessMemory(GetCurrentProcess(), memCreateMassege, hook, sizeof(hook), &bytesWriten);

	MessageBoxA(NULL, "Hello", "Hello", MB_OK);
	return 0;
}