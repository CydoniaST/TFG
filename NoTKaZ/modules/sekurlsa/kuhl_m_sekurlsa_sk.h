/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "globals_seKuRlSa.h"
#include "../modules/kull_m_cRyPTO_sk.h"
#include "kuhl_m_seKuRlSa.h"

typedef struct _KEYLIST_ENTRY {
	LIST_ENTRY navigator;
	BYTE key[32];
	DOUBLE entropy;
} KEYLIST_ENTRY, *PKEYLIST_ENTRY;

BOOL kuhl_m_seKuRlSa_sk_candidatekey_add(BYTE key[32], DOUBLE entropy);
void kuhl_m_seKuRlSa_sk_candidatekey_delete(PKEYLIST_ENTRY entry);
void kuhl_m_seKuRlSa_sk_candidatekey_descr(PKEYLIST_ENTRY entry);
void kuhl_m_seKuRlSa_sk_candidateKeYs_delete();
void kuhl_m_seKuRlSa_sk_candidateKeYs_descr();

DWORD kuhl_m_seKuRlSa_sk_search(PBYTE data, DWORD size, BOOL light);
DWORD kuhl_m_seKuRlSa_sk_search_file(LPCWSTR filename);

NTSTATUS kuhl_m_seKuRlSa_sk_bootKey(int argc, wchar_t* argv[]);
BOOL kuhl_m_seKuRlSa_sk_tryDecode(PLSAISO_DATA_BLOB blob, PBYTE *output, DWORD *cbOutput);