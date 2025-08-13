/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_handle.h"
#include <sddl.h>

extern NTSTATUS NTAPI NtCompareTokens(IN HANDLE FirstTokenHandle, IN HANDLE SecondTokenHandle, OUT PBOOLEAN Equal);

typedef BOOL (CALLBACK * PKULL_M_TOKEN_ENUM_CALLBACK) (HANDLE hToken, DWORD ptid, PVOID pvArg);

typedef struct _KULL_M_TOKEN_ENUM_DATA {
	PKULL_M_TOKEN_ENUM_CALLBACK callback;
	PVOID pvArg;
	BOOL mustContinue;
} KULL_M_TOKEN_ENUM_DATA, *PKULL_M_TOKEN_ENUM_DATA;

typedef struct _KULL_M_TOKEN_LIST {
	HANDLE hToken;
	DWORD ptid;
	struct _KULL_M_TOKEN_LIST *next;
} KULL_M_TOKEN_LIST, *PKULL_M_TOKEN_LIST;

BOOL kull_m_tOKEn_getTokens(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL kull_m_tOKEn_getTokensUnique(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL CALLBACK kull_m_tOKEn_getTokensUnique_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);
BOOL CALLBACK kull_m_tOKEn_getTokens_ProCeSs_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kull_m_tOKEn_getTokens_handles_callback(HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

BOOL kull_m_tOKEn_getNameDomainFromToken(HANDLE hToken, PWSTR * pName, PWSTR * pDomain, PWSTR * pSid, PSID_NAME_USE pSidNameUse);
BOOL kull_m_tOKEn_CheckTokenMembership(__in_opt HANDLE TokenHandle, __in PSID SidToCheck, __out PBOOL IsMember);
PCWCHAR kull_m_tOKEn_getSidNameUse(SID_NAME_USE SidNameUse);
BOOL kull_m_tOKEn_getNameDomainFromSID(PSID pSid, PWSTR * pName, PWSTR * pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system);
BOOL kull_m_tOKEn_getSidDomainFromName(PCWSTR pName, PSID * pSid, PWSTR * pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system);

BOOL kull_m_tOKEn_equal(IN HANDLE First, IN HANDLE Second);
PTOKEN_USER kull_m_tOKEn_getUserFromToken(HANDLE hToken);
PWSTR kull_m_tOKEn_getSidFromToken(HANDLE hToken);
PWSTR kull_m_tOKEn_getCurrentSid();
BOOL kull_m_tOKEn_isLocalAccount(__in_opt HANDLE TokenHandle, __out PBOOL IsMember);