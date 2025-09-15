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

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PMY_PEB_LDR_DATA Ldr;
} MY_PEB, * PMY_PEB;

HMODULE GetModuleBaseFromPEB(const wchar_t* moduleName)
{
    PMY_PEB peb = NULL;

#if defined(_M_X64)
    peb = (PMY_PEB)__readgsqword(0x60);
#elif defined(_M_IX86)
    peb = (PMY_PEB)__readfsdword(0x30);
#else
    return NULL;
#endif

    if (!peb || !peb->Ldr) return NULL;

    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    for (PLIST_ENTRY cur = head->Flink; cur != head; cur = cur->Flink)
    {
        PMY_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(cur, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length)
        {

            size_t len = entry->BaseDllName.Length / sizeof(wchar_t);
            if (len > 0 && len < 512) // sanity check
            {
                wchar_t tmp[513];
                wcsncpy_s(tmp, 513, entry->BaseDllName.Buffer, len);
                tmp[len] = L'\0';

                if (_wcsicmp(tmp, moduleName) == 0)
                    return (HMODULE)entry->DllBase;
            }
        }
    }

    return NULL;
}
