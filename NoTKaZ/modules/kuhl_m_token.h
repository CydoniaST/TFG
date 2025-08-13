/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_tOKEn.h"
#include "../modules/kull_m_net.h"
#include "kuhl_m_ProCeSs.h"

const KUHL_M kuhl_m_tOKEn;

//typedef enum _KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER {
//	TypeFree,
//	TypeAnonymous,
//	TypeIdentity,
//	TypeDelegation,
//	TypeImpersonate,
//	TypePrimary,
//} KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER, *PKUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER;

typedef struct _KUHL_M_TOKEN_ELEVATE_DATA {
	PSID pSid;
	PCWSTR pUsername;
	DWORD tOKEnId;
	BOOL eleVatEIt;
	BOOL runIt;
	PCWSTR pCommandLine;
	BOOL isSidDirectUser;

	//KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER filter;
	//BOOL isNeeded;
	//BOOL isMinimal;
} KUHL_M_TOKEN_ELEVATE_DATA, *PKUHL_M_TOKEN_ELEVATE_DATA;

void kuhl_m_tOKEn_displayAccount_sids(UCHAR l, DWORD count, PSID_AND_ATTRIBUTES sids);
void kuhl_m_tOKEn_displayAccount(HANDLE hToken, BOOL full);

NTSTATUS kuhl_m_tOKEn_whoami(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tOKEn_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tOKEn_eleVatE(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tOKEn_run(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_tOKEn_reVeRt(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_tOKEn_list_or_eleVatE(int argc, wchar_t * argv[], BOOL eleVatE, BOOL runIt);
BOOL CALLBACK kuhl_m_tOKEn_list_or_eleVatE_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);