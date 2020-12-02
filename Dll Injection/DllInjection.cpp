#include <iostream>
#include "stdio.h"
#include <Windows.h>
#include <tchar.h>

#ifdef UNICODE
#define LOAD_LIBRARY_VERSION "LoadLibraryW"
#else
#define LOAD_LIBRARY_VERSION "LoadLibraryA"
#endif


int _tmain(int argc, TCHAR argv[])
{
    TCHAR programName = argv[1];
    STARTUPINFO info = { sizeof(info) };
    PROCESS_INFORMATION processInfo;
    CreateProcess(NULL, &programName, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo);
    TCHAR dllPath = argv[2];
    DWORD sizeOfFilePath = _tcslen(&dllPath);
    LPVOID dllAddress = VirtualAllocEx(processInfo.hProcess, NULL, sizeOfFilePath, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(processInfo.hProcess, dllAddress, &dllPath, sizeOfFilePath, &bytesWritten);
    LPVOID dllRoutineAdress = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32")), LOAD_LIBRARY_VERSION);
    DWORD tid;
    printf("Dll inMemory address: %d", (DWORD)dllAddress);
    CreateRemoteThread(processInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dllRoutineAdress, dllAddress, 0, &tid);

}



