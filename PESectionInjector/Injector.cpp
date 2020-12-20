#include <Windows.h>


int main(int argc, PCHAR argv[]) {
	if (argv[1] && argv[2] && argv[3]) {
		LPCSTR targetFile = argv[1];
		LPCSTR sourceFile = argv[2];
		LPCSTR sectionName = argv[3];

		HANDLE hTargetFile = CreateFileA(targetFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		HANDLE hSourceFile = CreateFileA(sourceFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hTargetFile != INVALID_HANDLE_VALUE && hSourceFile != INVALID_HANDLE_VALUE) {

			DWORD targetFileSize = GetFileSize(hTargetFile, NULL);
			PBYTE targetFileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, targetFileSize);

			DWORD sourceFileSize = GetFileSize(hSourceFile, NULL);
			PBYTE sourceFileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);

			DWORD bytesRead = 0;
			DWORD bytesWriten = 0;

			if (ReadFile(hTargetFile, targetFileBuffer, targetFileSize, &bytesRead, NULL) && bytesRead == targetFileSize) {

				PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)targetFileBuffer;
				if (pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
					PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)(targetFileBuffer + pImageDosHeader->e_lfanew);
					PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(pImageNtHeader));
					DWORD numberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
					PIMAGE_SECTION_HEADER fileLastSection = ((PIMAGE_SECTION_HEADER)(pImageSectionHeader)+(numberOfSections - 1));

					DWORD fileImageBase = pImageNtHeader->OptionalHeader.ImageBase;
					DWORD lastSectionVirtualAddress = fileLastSection->VirtualAddress;
					DWORD lastSectionVirtualSize = fileLastSection->Misc.VirtualSize;

					DWORD sectionToAddVirtualAddress = fileImageBase + lastSectionVirtualAddress + lastSectionVirtualSize;

					PIMAGE_SECTION_HEADER newSection = &pImageSectionHeader[numberOfSections];
					ZeroMemory(newSection, sizeof(IMAGE_SECTION_HEADER));
					memcpy(newSection->Name, (PVOID)sectionName, 8);

					if (ReadFile(hSourceFile, sourceFileBuffer, sourceFileSize, &bytesRead, NULL) && bytesRead == sourceFileSize) {
						newSection->VirtualAddress = sectionToAddVirtualAddress;
						newSection->Misc.VirtualSize = sourceFileSize;
						newSection->PointerToRawData = (fileLastSection->PointerToRawData + fileLastSection->SizeOfRawData);
						newSection->SizeOfRawData = sourceFileSize;
						newSection->Characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
					}

					if (SetFilePointer(hTargetFile, newSection->PointerToRawData + newSection->SizeOfRawData, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
						SetEndOfFile(hTargetFile);
					}

					pImageNtHeader->OptionalHeader.SizeOfImage = newSection->VirtualAddress + newSection->Misc.VirtualSize;
					pImageNtHeader->FileHeader.NumberOfSections += 1;

					if (SetFilePointer(hTargetFile, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
						WriteFile(hTargetFile, targetFileBuffer, targetFileSize, &bytesWriten, NULL);
						WriteFile(hTargetFile, sourceFileBuffer, sourceFileSize, &bytesWriten, NULL);
					}

				}
			}
			HeapFree(GetProcessHeap(), NULL, targetFileBuffer);
			HeapFree(GetProcessHeap(), NULL, sourceFileBuffer);

		}
		CloseHandle(hTargetFile);
		CloseHandle(hSourceFile);
	}
	return 0;
}