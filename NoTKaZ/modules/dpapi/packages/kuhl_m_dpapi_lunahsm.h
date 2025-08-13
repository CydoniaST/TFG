/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dPApi.h"

NTSTATUS kuhl_m_dPApi_lunahsm(int argc, wchar_t * argv[]);

void kuhl_m_dPApi_safenet_ksp_registryparser(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hBase, int argc, wchar_t * argv[]);
void kuhl_m_dPApi_safenet_ksp_registry_user_parser(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hEntry, BYTE entropy[MD5_DIGEST_LENGTH], int argc, wchar_t * argv[]);

void kuhl_m_dPApi_safenet_ksp_entropy(IN LPCSTR identity, OUT BYTE entropy[MD5_DIGEST_LENGTH]);
LPSTR kuhl_m_dPApi_safenet_pk_password(IN LPCSTR server);