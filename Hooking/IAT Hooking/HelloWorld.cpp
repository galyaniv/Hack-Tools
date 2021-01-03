#include <Windows.h>
#include <iostream>

#define DLL_PATH L"IATHooking.dll"

using namespace std;
int WinMain(HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR     lpCmdLine,
    int       nShowCmd)
{
    HMODULE hModule = LoadLibrary(DLL_PATH);
    if (hModule != INVALID_HANDLE_VALUE && hModule != NULL) {
        MessageBox(NULL, L"hello", L"hello", NULL);
    }
    else
    {
        return 0;
    }
    return 1;
}