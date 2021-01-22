#include "includes.h"


void SpecialAPCRoutine() {
	printf("[+] Special APC routine\n");
}

void RegularAPCRoutine() {
	printf("[+] Regular APC routine\n");
}

int CreateSpecialAndRegularAPC() {

	HMODULE hNTDLL = LoadLibrary(L"ntdll");
	FARPROC fpNtQueueApcThreadEx = GetProcAddress(hNTDLL, "NtQueueApcThreadEx");
	_NtQueueApcThreadEx NtQueueApcThreadEx = (_NtQueueApcThreadEx)fpNtQueueApcThreadEx;

	USER_APC_OPTION userApcOption;
	userApcOption.UserApcFlags = QueueUserApcFlagsSpecialUserApc;

	// Only special APC will run
	NtQueueApcThreadEx(GetCurrentThread(), userApcOption, (PPS_APC_ROUTINE)&SpecialAPCRoutine, NULL, NULL, NULL);
	QueueUserAPC((PAPCFUNC)RegularAPCRoutine, GetCurrentThread(), NULL);
	
	Sleep(200);
	return 1;
}


int main() {
	CreateSpecialAndRegularAPC();
}