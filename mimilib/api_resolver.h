#ifndef API_RESOLVER_H
#define API_RESOLVER_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

    FARPROC getFunctionByHash(HMODULE hMod, DWORD targetHash);
    DWORD getHashFromString(const char* s);
    HMODULE GetModuleBaseFromPEB(const wchar_t* moduleName);

    typedef HANDLE(NTAPI* customCreateThread)(
        LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        SIZE_T                  dwStackSize,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        LPVOID                  lpParameter,
        DWORD                   dwCreationFlags,
        LPDWORD                 lpThreadId
        );

    typedef LPVOID(WINAPI* customVirtualAlloc)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect
        );

    typedef BOOL(WINAPI* customCreateProcessW)(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
        );

    typedef BOOL(WINAPI* customVirtualProtect)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
        );

    typedef HMODULE(WINAPI* customLoadLibraryW)(
        LPCWSTR lpLibFileName
        );

    typedef FARPROC(WINAPI* customGetProcAddress)(
        HMODULE hModule,
        LPCSTR  lpProcName
        );

    typedef BOOL(WINAPI* customWriteProcessMemory)(
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T* lpNumberOfBytesWritten
        );

    typedef BOOL(WINAPI* customReadProcessMemory)(
        HANDLE  hProcess,
        LPCVOID lpBaseAddress,
        LPVOID  lpBuffer,
        SIZE_T  nSize,
        SIZE_T* lpNumberOfBytesRead
        );

    typedef HANDLE(WINAPI* customOpenProcess)(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
        );

    typedef LPWCH(WINAPI* customGetEnvironmentStringsW)(void);

    typedef NTSTATUS(NTAPI* pNtTerminateProcess)(HANDLE, NTSTATUS);


    typedef int (WINAPI* customCompareStringW)(
        LCID     Locale,
        DWORD    dwCmpFlags,
        LPCWSTR  lpString1,
        int      cchCount1,
        LPCWSTR  lpString2,
        int      cchCount2
        );

    typedef HMODULE(WINAPI* customGetModuleHandleW)(
        LPCWSTR lpModuleName
        );

    typedef SECURITY_STATUS(WINAPI* PNCRYPTKEYDERIVATION)(
        NCRYPT_KEY_HANDLE hKey,
        PNCryptBufferDesc pParameterList,
        PBYTE pbDerivedKey,
        DWORD cbDerivedKey,
        PDWORD pcbResult,
        DWORD dwFlags
        );



#define H_CreateThread             0x00544e304
#define H_VirtualAlloc             0x0027a6ed3
#define H_VirtualProtect           0x0061c0e5d
#define H_LoadLibraryW             0x006b80253  
#define H_GetProcAddress           0x003db390f
#define H_WriteProcessMemory       0x004e6e3b0
#define H_ReadProcessMemory        0x004d77918
#define H_OpenProcess              0x002c8d7a8
#define H_GetEnvironmentStringsW   0x002839258
#define H_CompareStringW           0x00178974b
#define H_CreateProcessW           0x004f7db12  
#define H_GetModuleHandleW         0x003B3252
#define H_ncrypt_dll               0x008F1AAB
#define H_NCryptKeyDerivation      0x00A4E6C1
#define H_TERMINATIONPROCESS       0x1ABEE5

#ifdef __cplusplus
}
#endif

#endif
