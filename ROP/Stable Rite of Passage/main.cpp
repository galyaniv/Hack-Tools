#include "includes.h"

#define PROCESS_ID 40800

int main() {


	FULL_INFO* info = (FULL_INFO*)::malloc(sizeof(FULL_INFO));
	srop_class<FULL_INFO> srop(info);
	srop.data->remote_thread_info.processId = PROCESS_ID;
	srop.data->remote_thread_info.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, srop.data->remote_thread_info.processId);

	if (srop.data->remote_thread_info.hProcess == INVALID_HANDLE_VALUE || 
		srop.data->remote_thread_info.hProcess == NULL) {
		cout << "[+] Unable to get process handle\n" << EXIT_PROGRAM_COMMENT << endl;
		return 0;
	}

	DWORD success = srop.Start();
	if (!success) {
		cout << "[+] Stable Rite of Passage Failed :(\n" << EXIT_PROGRAM_COMMENT << endl;
		return 0;
	}

	cout << "[+] Stable Rite of Passage Succedded!!!\n"  << endl;
	return 1;
}