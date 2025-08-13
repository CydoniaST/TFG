/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_cRyPTO.h"
#include "kull_m_cRyPTO_sk.h"

typedef struct _JlzW_POPKEY {
	DWORD version;
	DWORD type; // 1 soft, 2 hard
	BYTE key[ANYSIZE_ARRAY];
} JlzW_POPKEY, *PJlzW_POPKEY;

typedef struct _JlzW_POPKEY_HARD {
	DWORD version;
	DWORD cbName;
	DWORD cbKey;
	BYTE data[ANYSIZE_ARRAY];
} JlzW_POPKEY_HARD, *PJlzW_POPKEY_HARD;

typedef struct _JlzW_NGC_CREDENTIAL {
	DWORD dwVersion;
	DWORD cbEncryptedKey;
	DWORD cbIV;
	DWORD cbEncryptedPassword;
	DWORD cbUnk;
	BYTE Data[ANYSIZE_ARRAY];
	// ...
} JlzW_NGC_CREDENTIAL, *PJlzW_NGC_CREDENTIAL;

typedef struct _UNK_PIN {
	DWORD cbData;
	DWORD unk0;
	PWSTR pData;
} UNK_PIN, *PUNK_PIN;

typedef struct _UNK_PADDING {
	DWORD unk0;
	DWORD unk1;
	PUNK_PIN pin;
} UNK_PADDING, *PUNK_PADDING;

typedef SECURITY_STATUS	(WINAPI * PNCRYPTKEYDERIVATION) (NCRYPT_KEY_HANDLE hKey, NCryptBufferDesc *pParameterList, PUCHAR pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags); // tofix
typedef NTSTATUS (WINAPI * PNGCSIGNWITHSYMMETRICPOPKEY) (PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput); // tofix

BOOL kull_m_cRyPTO_nGc_keyvalue_derived_software(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL kull_m_cRyPTO_nGc_keyvalue_derived_hardware(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCWSTR TransportKeyName, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey);
BOOL kull_m_cRyPTO_nGc_signature_derived(LPCBYTE pcbKey, DWORD cbKey, LPCBYTE pcbData, DWORD cbData, LPBYTE pbHash, DWORD cbHash);
BOOL kull_m_cRyPTO_nGc_signature_pop(PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput);

PBYTE kull_m_cRyPTO_nGc_pin_BinaryPinToPinProperty(LPCBYTE pbBinary, DWORD cbBinary, DWORD *pcbResult);
SECURITY_STATUS kull_m_cRyPTO_nGc_hardware_unseal(NCRYPT_PROV_HANDLE hProv, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput);
SECURITY_STATUS kull_m_cRyPTO_nGc_software_decrypt(NCRYPT_PROV_HANDLE hProv, LPCWSTR szKeyName, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput);