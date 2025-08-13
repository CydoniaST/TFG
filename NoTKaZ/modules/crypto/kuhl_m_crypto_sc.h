/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_cRyPTO.h"
#include <cardmod.h>
//#include "../../../modules/kull_m_cRyPTO.h"

NTSTATUS kuhl_m_cRyPTO_l_sc(int argc, wchar_t * argv[]);

void kuhl_m_cRyPTO_l_mdr(LPCWSTR szMdr, SCARDCONTEXT ctxScard, SCARDHANDLE hScard, LPCWSTR szModel, LPCBYTE pbAtr, DWORD cbAtr);
DWORD kuhl_m_cRyPTO_l_sc_provtypefromname(LPCWSTR szProvider);
PWSTR kuhl_m_cRyPTO_l_sc_containerFromReader(LPCWSTR reader);