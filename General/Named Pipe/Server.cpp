
#include <iostream>
#include <Windows.h>
#include <tchar.h>

int _tmain()
{

	HANDLE hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\namedPipe"),
		PIPE_ACCESS_OUTBOUND,
		PIPE_TYPE_BYTE,
		1,
		0,
		0,
		0,
		NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		std::cout << "[+] Creating named pipe failed. Error number " << GetLastError() << std::endl;
	}

	if (!ConnectNamedPipe(hPipe, NULL)) {
		std::cout << "[+] Connecting named pipe failed. Error number " << GetLastError() << std::endl;
	}

	const TCHAR *writebuffer = L"Buffer from server";
	DWORD bytesWriten = 0;
	if (!WriteFile(hPipe, writebuffer, wcslen(writebuffer)*sizeof(WCHAR), &bytesWriten, NULL)) {
		std::cout << "[+] Writing to named pipe failed. Error number " << GetLastError() << std::endl;
	}
	
	CloseHandle(hPipe);
	return 0;

}

