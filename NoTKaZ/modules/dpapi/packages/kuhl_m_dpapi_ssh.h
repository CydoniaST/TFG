/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dPApi.h"
#include "../../../../modules/kull_m_registry.h"
#include "../../kuhl_m_tOKEn.h"

NTSTATUS kuhl_m_dPApi_ssh(int argc, wchar_t * argv[]);

void kuhl_m_dPApi_ssh_keys4user(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hUser, LPCWSTR szSID, int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_dPApi_ssh_impersonate(HANDLE hToken, DWORD ptid, PVOID pvArg);
void kuhl_m_dPApi_ssh_getKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hEntry, int argc, wchar_t * argv[], HANDLE hToken);
BOOL kuhl_m_dPApi_ssh_getRSAfromRAW(LPCBYTE data, DWORD szData);
void kuhl_m_dPApi_ssh_ParseKeyElement(PBYTE *pRaw, PBYTE *pData, DWORD *pszData);

typedef struct _KUHL_M_DPAPI_SSH_TOKEN{
	PSID pSid;
	HANDLE hToken;
} KUHL_M_DPAPI_SSH_TOKEN, *PKUHL_M_DPAPI_SSH_TOKEN;

/* Key types */
enum sshkey_types {
	KEY_RSA,
	KEY_DSA,
	KEY_ECDSA,
	KEY_ED25519,
	KEY_RSA_CERT,
	KEY_DSA_CERT,
	KEY_ECDSA_CERT,
	KEY_ED25519_CERT,
	KEY_XMSS,
	KEY_XMSS_CERT,
	KEY_UNSPEC
};