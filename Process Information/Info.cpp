#include <iostream>
#include <Windows.h>

int main()
{
    DWORD peb;
    DWORD basePointer;
    DWORD ldrPointer;

    DWORD pid = GetCurrentProcessId();
    DWORD base;
    DWORD ldr;

    _asm {
        mov eax, FS: [0x30]
        mov peb, eax
        add eax, 8
        mov basePointer, eax
        add eax, 4
        mov ldrPointer, eax
    }
    CopyMemory(&base, (DWORD*)basePointer, sizeof(DWORD));
    CopyMemory(&ldr, (DWORD*)ldrPointer, sizeof(DWORD));
    
    printf("[+] Process Id: %d\n[+] PEB: 0x%p\n[+] baseImage: 0x%p\n[+] ldr: 0x%p\n", pid, (PVOID)peb, (PVOID)base, (PVOID)(ldr));
}
