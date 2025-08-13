/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "../kuhl_m.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_dPApi.h"

#include "kuhl_m_dPApi_oe.h"
#include "packages/kuhl_m_dPApi_keys.h"
#include "packages/kuhl_m_dPApi_crEds.h"
#include "packages/kuhl_m_dPApi_wlan.h"
#include "packages/kuhl_m_dPApi_chrome.h"
#include "packages/kuhl_m_dPApi_ssh.h"
#include "packages/kuhl_m_dPApi_rdg.h"
#include "packages/kuhl_m_dPApi_powershell.h"
#include "packages/kuhl_m_dPApi_lunahsm.h"
#include "packages/kuhl_m_dPApi_clOuDAp.h"
#include "packages/kuhl_m_dPApi_sccm.h"
#include "packages/kuhl_m_dPApi_citrix.h"

const KUHL_M kuhl_m_dPApi;

NTSTATUS kuhl_m_dPApi_blob(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dPApi_protect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dPApi_masTerKeY(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dPApi_crEdHiSt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dPApi_create(int argc, wchar_t * argv[]);

BOOL kuhl_m_dPApi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, int argc, wchar_t * argv[], LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCWSTR pText);
void kuhl_m_dPApi_display_MasterkeyInfosAndFree(LPCGUID guid, PVOID data, DWORD dataLen, PSID sid);
void kuhl_m_dPApi_display_CredHist(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID ntlm, LPCVOID sha1);