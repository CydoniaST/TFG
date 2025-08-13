#include "api_resolver.h"
#include <Windows.h>
#include <stdio.h> 
#include <winternl.h>


typedef struct _UNICODE_STRING_CUSTOM {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_CUSTOM, * PUNICODE_STRING_CUSTOM;

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_CUSTOM FullDllName;
    UNICODE_STRING_CUSTOM BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM, * PLDR_DATA_TABLE_ENTRY_CUSTOM;

DWORD customHash(const char* str) {
    DWORD hash = 0x12345678;
    while (*str) {
        hash ^= *str;
        hash = (hash << 5) | (hash >> 27);
        str++;
    }
    return hash;
}

HMODULE getModuleByHash(DWORD targetHash) {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY_CUSTOM entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);
        char name[MAX_PATH] = { 0 };

        for (size_t i = 0; i < (size_t)(entry->BaseDllName.Length / 2) && i < MAX_PATH - 1; i++)
            name[i] = (char)entry->BaseDllName.Buffer[i];

        if (customHash(name) == targetHash)
            return (HMODULE)entry->DllBase;

        current = current->Flink;
    }
    return NULL;
}


DWORD getHashFromString(const char* string) {
    size_t stringLength = strnlen_s(string, 50);
    DWORD hash = 0x35;

    for (size_t i = 0; i < stringLength; i++) {
        hash += (hash * 0xab10f29f + (unsigned char)string[i]) & 0xffffff;
    }
    return hash;
}

PDWORD getFunctionAddressByHash(char* library, DWORD hash) {
    PDWORD functionAddress = (PDWORD)0;

    HMODULE libraryBase = LoadLibraryA(library);
    if (!libraryBase) return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++) {
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char* functionName = (char*)functionNameVA;

        DWORD functionNameHash = getHashFromString(functionName);

        if (functionNameHash == hash) {
            DWORD_PTR functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
            printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
            return functionAddress;
        }
    }
    return NULL;
}
