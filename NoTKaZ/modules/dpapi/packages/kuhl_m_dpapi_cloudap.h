/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dPApi.h"
#include "../../../../modules/kull_m_cRyPTO_nGc.h"
#include <time.h>

NTSTATUS kuhl_m_dPApi_clOuDAp_keyvalue_derived(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dPApi_clOuDAp_fromreg(int argc, wchar_t * argv[]);

PSTR generate_simpleHeader(PCSTR Alg, LPCBYTE Context, DWORD cbContext);
PSTR generate_simplePayload(PCWSTR PrimaryRefreshToken, __time32_t *iat);
PSTR generate_simpleSignature(LPCBYTE Context, DWORD cbContext, PCWSTR PrimaryRefreshToken, __time32_t *iat, LPCBYTE Key, DWORD cbKey, OPTIONAL LPCBYTE SeedLabel, OPTIONAL DWORD cbSeedLabel);