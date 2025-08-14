#include "api_resolver.h"
#include <Windows.h>
#include <stdint.h>
#include <string.h>

typedef FARPROC(WINAPI* CustomGetProc)(HMODULE, DWORD);

// Función de hash idéntica a la del laboratorio de ired.team
DWORD getHashFromString(const char* s) {
    DWORD hash = 0x35;
    while (*s) {
        hash = ((hash * 0xAB10F29F) + (BYTE)(*s)) & 0x00FFFFFF;
        s++;
    }
    return hash;
}

FARPROC getFunctionByHash(HMODULE hMod, DWORD targetHash) {
    if (!hMod) return NULL;

    // Cabeceras PE
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Export table
    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return NULL;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + expRVA);

    DWORD* names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)hMod + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)hMod + names[i];
        // Cálculo del hash
        if (getHashFromString(name) == targetHash) {
            WORD ordIndex = ords[i];
            DWORD funcRVA = funcs[ordIndex];
            return (FARPROC)((BYTE*)hMod + funcRVA);
        }
    }
    return NULL;
}
