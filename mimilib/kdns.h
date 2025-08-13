/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "utils.h"

#define PLUGIN_ALLOCATOR_FUNCTION PVOID
#define PLUGIN_FREE_FUNCTION PVOID
#define PDB_RECORD PVOID

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction);
DWORD WINAPI kdns_DnsPluginCleanup();
DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead);
// DnsPluginQuery2
// DnsPluginQueryZoneScope
// DnsPluginQueryServerScope
// DnsPluginQueryCacheScope