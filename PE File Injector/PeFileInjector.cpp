#include <Windows.h>
#include <tchar.h>

DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}
// command: ./Injector.exe <target_PE> <dll_path> <section_name>
int _tmain(int args, PTCHAR argv[]) {

	if (argv[1] && argv[2] && argv[3]) {
		PWCHAR FileToAddSection = argv[1];
		PWCHAR dllFile = argv[2];
		PWCHAR OnewSectionName = argv[3];
		CHAR newSectionName[MAX_PATH];
		WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, OnewSectionName, -1, newSectionName, sizeof(PCHAR), NULL, NULL);


		HANDLE hFileToAddSection = CreateFileW(FileToAddSection, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFileToAddSection != INVALID_HANDLE_VALUE) {
			DWORD FileToAddSectionSize = GetFileSize(hFileToAddSection, NULL);
			PBYTE fileBuffer = (PBYTE)LocalAlloc(LPTR, FileToAddSectionSize);
			DWORD returnedBytes;

			if (ReadFile(hFileToAddSection, fileBuffer, FileToAddSectionSize, &returnedBytes, nullptr) && returnedBytes == FileToAddSectionSize) {
				PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
				if (imageDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
					PIMAGE_FILE_HEADER imageFileHeader = (PIMAGE_FILE_HEADER)(fileBuffer + imageDosHeader->e_lfanew + sizeof(DWORD));
					PIMAGE_OPTIONAL_HEADER imageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(fileBuffer + imageDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
					PIMAGE_SECTION_HEADER imageSectionHeader = (PIMAGE_SECTION_HEADER)(fileBuffer + imageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
					WORD NumberOfSections = imageFileHeader->NumberOfSections;

					ZeroMemory(&imageSectionHeader[NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
					CopyMemory(&imageSectionHeader[NumberOfSections].Name, newSectionName, 8);

					HANDLE hDllFile = CreateFileW(dllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hDllFile != INVALID_HANDLE_VALUE) {
						DWORD dllFileSize = GetFileSize(hDllFile, NULL);
						if (dllFileSize > 0) {
							PBYTE fileBuffer2 = (PBYTE)LocalAlloc(LPTR, dllFileSize);
							if (fileBuffer2 != ERROR) {
								DWORD dllFileReturnedBytes;
								if (ReadFile(hDllFile, fileBuffer2, dllFileSize, &dllFileReturnedBytes, NULL) && dllFileReturnedBytes == dllFileSize) {

									imageSectionHeader[NumberOfSections].Misc.VirtualSize = align(dllFileSize, imageOptionalHeader->SectionAlignment, 0);
									imageSectionHeader[NumberOfSections].VirtualAddress = align(imageSectionHeader[imageFileHeader->NumberOfSections - 1].Misc.VirtualSize, imageOptionalHeader->SectionAlignment, imageSectionHeader[imageFileHeader->NumberOfSections - 1].VirtualAddress);
									imageSectionHeader[NumberOfSections].SizeOfRawData = align(dllFileSize, imageOptionalHeader->FileAlignment, 0);
									imageSectionHeader[NumberOfSections].PointerToRawData = align(imageSectionHeader[imageFileHeader->NumberOfSections - 1].SizeOfRawData, imageOptionalHeader->FileAlignment, imageSectionHeader[imageFileHeader->NumberOfSections - 1].PointerToRawData);
									imageSectionHeader[NumberOfSections].Characteristics = 0xE00000E0;

									if (SetFilePointer(hFileToAddSection, imageSectionHeader[NumberOfSections].PointerToRawData + imageSectionHeader[NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
										SetEndOfFile(hFileToAddSection);
									}
									
									imageOptionalHeader->SizeOfImage = imageSectionHeader[NumberOfSections].VirtualAddress + imageSectionHeader[NumberOfSections].Misc.VirtualSize;
									imageFileHeader->NumberOfSections += 1;

									if (SetFilePointer(hFileToAddSection, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
										
										WriteFile(hFileToAddSection, fileBuffer, FileToAddSectionSize, &returnedBytes, NULL);
										
										
									}
									WriteFile(hFileToAddSection, fileBuffer2, dllFileSize, &dllFileReturnedBytes, NULL);
									


								}
							}
							LocalFree(fileBuffer2);
						}

					}
					CloseHandle(hDllFile);
				}
			}
			LocalFree(fileBuffer);
		}
		CloseHandle(hFileToAddSection);

	}
}

