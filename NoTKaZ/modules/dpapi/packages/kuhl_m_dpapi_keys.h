/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dPApi.h"
#include "../../kuhl_m_cRyPTO.h"
#include "../modules/kull_m_key.h"

NTSTATUS kuhl_m_dPApi_keys_cng(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dPApi_keys_capi(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dPApi_keys_tpm(int argc, wchar_t * argv[]);

void kuhl_m_dPApi_keys_tpm_descr(LPCVOID data, DWORD dwData);

typedef struct _KUHL_M_DPAPI_KEYS_TPM_TLV {
	DWORD Tag;
	DWORD Length;
	BYTE Data[ANYSIZE_ARRAY];
} KUHL_M_DPAPI_KEYS_TPM_TLV, *PKUHL_M_DPAPI_KEYS_TPM_TLV;