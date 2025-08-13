/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dPApi.h"
#include "../../../../modules/kull_m_string.h"
#include "../../../../modules/kull_m_cRyPTO.h"
#include <wbemidl.h>

typedef struct _SCCM_Policy_Secret {
	DWORD cbData;
	BYTE data[ANYSIZE_ARRAY];
} SCCM_Policy_Secret, *PSCCM_Policy_Secret;

NTSTATUS kuhl_m_dPApi_sccm_networkaccessaccount(int argc, wchar_t * argv[]);

BOOL kuhl_m_dPApi_sccm_XML_Data_to_bin(BSTR szData, PSCCM_Policy_Secret * ppPolicySecret, PDWORD pcbPolicySecret);