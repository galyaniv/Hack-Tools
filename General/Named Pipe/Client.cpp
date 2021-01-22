// IPC.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <tchar.h>

int _tmain()
{

	TCHAR namePipe[] = TEXT("\\\\.\\pipe\\namedPipe");
	HANDLE hPipe = CreateFile(namePipe, GENERIC_READ , FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hPipe == INVALID_HANDLE_VALUE ) {
		std::cout << "[+] Error in creating pipe handle\n";
		return 1;
	}

	TCHAR readBuffer[128];
	DWORD readBytes = 0;
	if (!ReadFile(hPipe, readBuffer, sizeof(readBuffer), &readBytes, NULL)) {
		std::cout << "[+] Error in reading from named pipe. Error number - " << GetLastError() << std::endl;
		return 1;
	}
	readBuffer[readBytes / sizeof(TCHAR)] = '\0';
	std::wcout << "[+] Message from server: " << readBuffer << std::endl;
	
	CloseHandle(hPipe);
	return 0;
}


