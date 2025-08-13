/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kuhl_m_dPApi.h"
#include "../modules/rpc/kull_m_rpc_dPApi-entries.h"

typedef struct _KUHL_M_DPAPI_OE_MASTERKEY_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_MASTERKEY_ENTRY data;
} KUHL_M_DPAPI_OE_MASTERKEY_ENTRY, *PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY;

#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4		0x00000001
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1	0x00000002
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4p	0x00000004
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID	0x80000000
typedef struct _KUHL_M_DPAPI_OE_CREDENTIAL_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_CREDENTIAL_ENTRY data;
/*	
	PVOID DPAPI_SYSTEM_machine;
	PVOID DPAPI_SYSTEM_user;
*/
} KUHL_M_DPAPI_OE_CREDENTIAL_ENTRY, *PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY;

typedef struct _KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_DOMAINKEY_ENTRY data;
} KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY, *PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY;

NTSTATUS kuhl_m_dPApi_oe_clean();
NTSTATUS kuhl_m_dPApi_oe_caCHe(int argc, wchar_t * argv[]);
BOOL kuhl_m_dPApi_oe_is_sid_valid_ForCacheOrAuto(PSID sid, LPCWSTR szSid, BOOL AutoOrCache);
BOOL kuhl_m_dPApi_oe_autosid(LPCWSTR filename, LPWSTR * pSid);

LIST_ENTRY gDPAPI_Masterkeys;
LIST_ENTRY gDPAPI_Credentials;
LIST_ENTRY gDPAPI_Domainkeys;

PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY kuhl_m_dPApi_oe_masTerKeY_get(LPCGUID guid);
BOOL kuhl_m_dPApi_oe_masTerKeY_add(LPCGUID guid, LPCVOID key, DWORD keyLen);
void kuhl_m_dPApi_oe_masTerKeY_delete(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry);
void kuhl_m_dPApi_oe_masTerKeY_descr(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry);
void kuhl_m_dPApi_oe_masTerKeYs_delete();
void kuhl_m_dPApi_oe_masTerKeYs_descr();

PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY kuhl_m_dPApi_oe_crEdential_get(LPCWSTR sid, LPCGUID guid);
BOOL kuhl_m_dPApi_oe_crEdential_add(LPCWSTR sid, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password);
void kuhl_m_dPApi_oe_crEdential_delete(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry);
void kuhl_m_dPApi_oe_crEdential_descr(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry);
void kuhl_m_dPApi_oe_crEdentials_delete();
void kuhl_m_dPApi_oe_crEdentials_descr();

PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY kuhl_m_dPApi_oe_domainkey_get(LPCGUID guid);
BOOL kuhl_m_dPApi_oe_domainkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen, BOOL isNewKey);
void kuhl_m_dPApi_oe_domainkey_delete(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry);
void kuhl_m_dPApi_oe_domainkey_descr(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry);
void kuhl_m_dPApi_oe_domainkeys_delete();
void kuhl_m_dPApi_oe_domainkeys_descr();

BOOL kuhl_m_dPApi_oe_crEdential_addtoEntry(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password);
BOOL kuhl_m_dPApi_oe_crEdential_copyEntryWithNewGuid(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid);

BOOL kuhl_m_dPApi_oe_SaveToFile(LPCWSTR filename);
BOOL kuhl_m_dPApi_oe_LoadFromFile(LPCWSTR filename);