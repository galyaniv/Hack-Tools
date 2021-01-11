#include "ROP.h"

#define MODULES_NUMBER 5

void *memmem(const void *haystack, size_t haystack_len, const void* needle, size_t needle_len)
{
	if (haystack == NULL) return NULL; 
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL; 
	if (needle_len == 0) return NULL;

	for (const char* h = (char*)haystack; haystack_len >= needle_len; h++, haystack_len--) {
		if (!memcmp(h, needle, needle_len)) {
			return (void *)h;
		}
	}
	return NULL;
}

PVOID SearchRopGadgets(const void* ropGadget, size_t ropGadgetSize) {
	DWORD i = 0;
	LPCWSTR pModules[MODULES_NUMBER] = { L"ntdll", L"kernel32", L"user32", L"kernelbase", L"gdi32" };

	for (i = 0; i < MODULES_NUMBER; i++) {
		HANDLE hModule = GetModuleHandle(pModules[i]);
		PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)hModule + imageDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER imageSectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(imageNtHeaders);

		DWORD numberOfSections = imageNtHeaders->FileHeader.NumberOfSections;

		for (i = 0; i < numberOfSections; i++) {
			if (lstrcmp((LPCWSTR)imageSectionHeader->Name, L".text")) break;
		}

		PVOID ropGadgetAddress = memmem((char*)imageSectionHeader, imageSectionHeader->SizeOfRawData, ropGadget, ropGadgetSize);

		if (ropGadgetAddress != NULL) return ropGadgetAddress;
	}
	return NULL;
}

int main()
{
	PVOID _add_rsp_0x28 = SearchRopGadgets("\x48\x83\xC4\x28", 4);
	return 0;
}