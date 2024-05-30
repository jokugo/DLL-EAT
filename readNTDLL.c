#include <stdio.h>
#include <windows.h>

void export(HMODULE hModule) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + exportDirRVA);

    DWORD* functions = (DWORD*)((DWORD_PTR)hModule + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)((DWORD_PTR)hModule + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((DWORD_PTR)hModule + exportDir->AddressOfNameOrdinals);

    printf ("ntdll functions:\n");
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* functionName = (char*)((DWORD_PTR)hModule + names[i]);
        FARPROC functionAddress = (FARPROC)((DWORD_PTR)hModule + functions[ordinals[i]]);
        printf("%s at address 0x%p\n", functionName, functionAddress);
    }
}

int main() {
    HMODULE hNtdll = LoadLibrary("ntdll.dll");

    export(hNtdll);
    FreeLibrary(hNtdll);
    return 0;
}
