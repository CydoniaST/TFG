/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include "../../../modules/kull_m_string.h"
#include "../../../modules/kull_m_cRyPTO.h"//*_system.h"
//#include "../kuhl_m_cRyPTO.h"

typedef struct _JlzW_KEY_INFO {
	CRYPT_KEY_PROV_INFO keyInfos;
	LPSTR pin;
	DWORD dwKeyFlags;
	WORD wKeySize;
	HCRYPTPROV hProv;
} JlzW_KEY_INFO, *PJlzW_KEY_INFO;

typedef struct _JlzW_CERT_INFO {
	LPFILETIME notbefore; // do NOT move
	LPFILETIME notafter; // do NOT move
	LPCWSTR cn;
	LPCWSTR ou;
	LPCWSTR o;
	LPCWSTR c;
	LPCWSTR sn;
	WORD ku;
	LPSTR algorithm;
	BOOL isAC;
	PCERT_EXTENSION eku;
	PCERT_EXTENSION san;
	PCERT_EXTENSION cdp;
} JlzW_CERT_INFO, *PJlzW_CERT_INFO;

typedef struct _JlzW_CRL_INFO {
	LPFILETIME thisupdate; // do NOT move
	LPFILETIME nextupdate; // do NOT move
	LPSTR algorithm;
	int crlnumber;
	// ...
} JlzW_CRL_INFO, *PJlzW_CRL_INFO;

typedef struct _JlzW_SIGNER {
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv;
	DWORD dwKeySpec;
	FILETIME NotBefore;
	FILETIME NotAfter;
	CERT_NAME_BLOB Subject;
} JlzW_SIGNER, *PJlzW_SIGNER;

PWSTR kuhl_m_cRyPTO_pki_getCertificateName(PCERT_NAME_BLOB blob);

NTSTATUS kuhl_m_cRyPTO_c_sc_auth(int argc, wchar_t * argv[]);
BOOL kuhl_m_cRyPTO_c_sc_auth_quickEncode(__in LPCSTR lpszStructType, __in const void *pvStructInfo, PDATA_BLOB data);