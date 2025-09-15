#include "api_resolver.h"
#include <Windows.h>
#include <stdint.h>
#include <string.h>

// Basado en  ired.team
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
        if (getHashFromString(name) == targetHash) {
            WORD ordIndex = ords[i];
            DWORD funcRVA = funcs[ordIndex];
            return (FARPROC)((BYTE*)hMod + funcRVA);
        }
    }
    return NULL;
}

//Nuevo

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING, * PMY_UNICODE_STRING;

typedef struct _MY_PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;



typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    PVOID      Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID      Reserved2[2];
    PVOID      DllBase;
    PVOID      EntryPoint;
    PVOID      Reserved3;
    MY_UNICODE_STRING FullDllName;
    BYTE       Reserved4[8];
    PVOID      Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG      TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;



typedef struct _MY_PEB {
    BYTE              Reserved1[2];
    BYTE              BeingDebugged;
    BYTE              Reserved2[1];
    PVOID             Reserved3[2];
    PMY_PEB_LDR_DATA  Ldr;

} MY_PEB, * PMY_PEB;



HMODULE GetModuleBaseFromPEB(const wchar_t* moduleName) {
    PMY_PEB peb = (PMY_PEB)__readgsqword(0x60);  // PEB location in 64-bit
    PMY_PEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* moduleList = &ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* entry = moduleList->Flink; entry != moduleList; entry = entry->Flink) {
        PMY_LDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(entry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (_wcsicmp(moduleEntry->FullDllName.Buffer, moduleName) == 0) {
            return (HMODULE)moduleEntry->DllBase;
        }
    }
    return NULL;
}
