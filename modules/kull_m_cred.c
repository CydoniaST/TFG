/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kull_m_crEd.h"

const wchar_t KULL_M_CRED_ENTROPY_CRED_DER[37] = L"\x0184\x0188\x0194\x00c8\x00e0\x00d8\x00e4\x0198\x00b4\x00e4\x0188\x00d0\x00dc\x00b4\x00d0\x018c\x0190\x00e4\x00b4\x0184\x00cc\x00d4\x00e0\x00b4\x018c\x00c8\x00c8\x00e4\x00c0\x00d0\x0190\x0188\x0184\x00dc\x0198\x00dc";
const wchar_t KULL_M_CRED_ENTROPYDOM_CRED_DER[37] = L"\x00e0\x00c8\x0108\x0110\x00c0\x0114\x00d8\x00dc\x00b4\x00e4\x0118\x0114\x0104\x00b4\x00d0\x00dc\x00d0\x00e0\x00b4\x00e0\x00d8\x00dc\x00c8\x00b4\x0110\x00d4\x0114\x0118\x0114\x00d4\x0108\x00dc\x00dc\x00e4\x0108\x00c0";
//wchar_t entropyCred[] = L"abe2869f-9b47-4cd9-a358-c22904dba7f7";
//wchar_t entropyDomCred[] = L"82BD0E67-9FEA-4748-8672-D5EFE5B779B0";
//DWORD i;
//for(i = 0; i < ARRAYSIZE(entropyCred); i++)
//	entropyCred[i] <<= 2;
//for(i = 0; i < ARRAYSIZE(entropyDomCred); i++)
//	entropyDomCred[i] <<= 2;

PKULL_M_CRED_BLOB kull_m_crEd_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_BLOB crEd = NULL;
	if(crEd = (PKULL_M_CRED_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_CRED_BLOB)))
	{
		RtlCopyMemory(crEd, data, FIELD_OFFSET(KULL_M_CRED_BLOB, TargetName));
		crEd->TargetName = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_BLOB, TargetName));
		crEd->dwUnkData = *(PDWORD) ((PBYTE) crEd->TargetName + crEd->dwTargetName);
		crEd->UnkData = (LPWSTR) ((PBYTE) crEd->TargetName + crEd->dwTargetName + sizeof(DWORD));
		crEd->dwComment = *(PDWORD) ((PBYTE) crEd->UnkData + crEd->dwUnkData);
		crEd->Comment = (LPWSTR) ((PBYTE) crEd->UnkData + crEd->dwUnkData + sizeof(DWORD));
		crEd->dwTargetAlias = *(PDWORD) ((PBYTE) crEd->Comment + crEd->dwComment);
		crEd->TargetAlias = (LPWSTR) ((PBYTE) crEd->Comment + crEd->dwComment + sizeof(DWORD));
		crEd->dwUserName = *(PDWORD) ((PBYTE) crEd->TargetAlias + crEd->dwTargetAlias);
		crEd->UserName = (LPWSTR) ((PBYTE) crEd->TargetAlias + crEd->dwTargetAlias + sizeof(DWORD));
		crEd->CredentialBlobSize = *(PDWORD) ((PBYTE) crEd->UserName + crEd->dwUserName);
		crEd->CredentialBlob = (PBYTE) crEd->UserName + crEd->dwUserName + sizeof(DWORD);
		
		if(crEd->AttributeCount)
			kull_m_crEd_attributes_create(((PBYTE) crEd->CredentialBlob + crEd->CredentialBlobSize + (crEd->CredentialBlobSize & 1)), &crEd->Attributes, crEd->AttributeCount);			

		kull_m_string_ptr_replace(&crEd->TargetName, crEd->dwTargetName);
		kull_m_string_ptr_replace(&crEd->TargetAlias, crEd->dwTargetAlias);
		kull_m_string_ptr_replace(&crEd->Comment, crEd->dwComment);
		kull_m_string_ptr_replace(&crEd->UnkData, crEd->dwUnkData);
		kull_m_string_ptr_replace(&crEd->UserName, crEd->dwUserName);
		kull_m_string_ptr_replace(&crEd->CredentialBlob, crEd->CredentialBlobSize);
	}
	return crEd;
}

void kull_m_crEd_delete(PKULL_M_CRED_BLOB crEd)
{
	if(crEd)
	{
		if(crEd->TargetName)
			LocalFree(crEd->TargetName);
		if(crEd->UnkData)
			LocalFree(crEd->UnkData);
		if(crEd->Comment)
			LocalFree(crEd->Comment);
		if(crEd->TargetAlias)
			LocalFree(crEd->TargetAlias);
		if(crEd->UserName)
			LocalFree(crEd->UserName);
		if(crEd->CredentialBlob)
			LocalFree(crEd->CredentialBlob);
		if(crEd->Attributes)
			kull_m_crEd_attributes_delete(crEd->Attributes, crEd->AttributeCount);
		LocalFree(crEd);
	}
}

void kull_m_crEd_descr(DWORD level, PKULL_M_CRED_BLOB crEd)
{
	kprintf(L"%*s" L"**CREDENTIAL**\n", level << 1, L"");
	if(crEd)
	{
		kprintf(L"%*s" L"  crEdFlags      : %08x - %u\n", level << 1, L"", crEd->crEdFlags, crEd->crEdFlags);
		kprintf(L"%*s" L"  crEdSize       : %08x - %u\n", level << 1, L"", crEd->crEdSize, crEd->crEdSize);
		kprintf(L"%*s" L"  crEdUnk0       : %08x - %u\n\n", level << 1, L"", crEd->crEdUnk0, crEd->crEdUnk0);
		kprintf(L"%*s" L"  Type           : %08x - %u - %s\n", level << 1, L"", crEd->Type, crEd->Type, kull_m_crEd_CredType(crEd->Type));
		kprintf(L"%*s" L"  Flags          : %08x - %u\n", level << 1, L"", crEd->Flags, crEd->Flags);
		kprintf(L"%*s" L"  LastWritten    : ", level << 1, L""); kull_m_string_displayFileTime(&crEd->LastWritten); kprintf(L"\n");
		kprintf(L"%*s" L"  unkFlagsOrSize : %08x - %u\n", level << 1, L"", crEd->unkFlagsOrSize, crEd->unkFlagsOrSize);
		kprintf(L"%*s" L"  Persist        : %08x - %u - %s\n", level << 1, L"", crEd->Persist, crEd->Persist, kull_m_crEd_CredPersist(crEd->Persist));
		kprintf(L"%*s" L"  AttributeCount : %08x - %u\n", level << 1, L"", crEd->AttributeCount, crEd->AttributeCount);
		kprintf(L"%*s" L"  unk0           : %08x - %u\n", level << 1, L"", crEd->unk0, crEd->unk0);
		kprintf(L"%*s" L"  unk1           : %08x - %u\n", level << 1, L"", crEd->unk1, crEd->unk1);
		kprintf(L"%*s" L"  TargetName     : %s\n", level << 1, L"", crEd->TargetName);
		kprintf(L"%*s" L"  UnkData        : %s\n", level << 1, L"", crEd->UnkData);
		kprintf(L"%*s" L"  Comment        : %s\n", level << 1, L"", crEd->Comment);
		kprintf(L"%*s" L"  TargetAlias    : %s\n", level << 1, L"", crEd->TargetAlias);
		kprintf(L"%*s" L"  UserName       : %s\n", level << 1, L"", crEd->UserName);
		kprintf(L"%*s" L"  CredentialBlob : ", level << 1, L"");
		kull_m_string_printSuspectUnicodeString(crEd->CredentialBlob, crEd->CredentialBlobSize);
		kprintf(L"\n");
		kprintf(L"%*s" L"  Attributes     : %u\n", level << 1, L"", crEd->AttributeCount);
		kull_m_crEd_attributes_descr(level + 1, crEd->Attributes, crEd->AttributeCount);
	}
}

BOOL kull_m_crEd_attributes_create(PVOID data, PKULL_M_CRED_ATTRIBUTE **Attributes, DWORD count)
{
	BOOL status = FALSE;
	DWORD i, j;
	
	if((*Attributes) = (PKULL_M_CRED_ATTRIBUTE *) LocalAlloc(LPTR, count * sizeof(PKULL_M_CRED_ATTRIBUTE)))
	{
		for(i = 0, j = 0, status = TRUE; (i < count) && status; i++)
		{
			if((*Attributes)[i] = kull_m_crEd_attribute_create((PBYTE) data + j))
				j +=  sizeof(KULL_M_CRED_ATTRIBUTE) - 2 * sizeof(PVOID) + (*Attributes)[i]->dwKeyword + (*Attributes)[i]->ValueSize;
			else status = FALSE;
		}
	}
	if(!status)
	{
		kull_m_crEd_attributes_delete(*Attributes, count);
		*Attributes = NULL;
	}
	return status;
}

void kull_m_crEd_attributes_delete(PKULL_M_CRED_ATTRIBUTE *Attributes, DWORD count)
{
	DWORD i;
	if(Attributes)
	{
		for(i = 0; i < count; i++)
			kull_m_crEd_attribute_delete(Attributes[i]);
		LocalFree(Attributes);
	}
}

void kull_m_crEd_attributes_descr(DWORD level, PKULL_M_CRED_ATTRIBUTE *Attributes, DWORD count)
{
	DWORD i;
	if(count && Attributes)
		for(i = 0; i < count; i++)
			kull_m_crEd_attribute_descr(level, Attributes[i]);
}

PKULL_M_CRED_ATTRIBUTE kull_m_crEd_attribute_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_ATTRIBUTE Attribute = NULL;
	if(Attribute = (PKULL_M_CRED_ATTRIBUTE) LocalAlloc(LPTR, sizeof(KULL_M_CRED_ATTRIBUTE)))
	{
		RtlCopyMemory(Attribute, data, FIELD_OFFSET(KULL_M_CRED_ATTRIBUTE, Keyword));
		Attribute->Keyword = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_ATTRIBUTE, Keyword));
		Attribute->ValueSize = *(PDWORD) ((PBYTE) Attribute->Keyword + Attribute->dwKeyword);
		Attribute->Value = (PBYTE) Attribute->Keyword + Attribute->dwKeyword + sizeof(DWORD);

		kull_m_string_ptr_replace(&Attribute->Keyword, Attribute->dwKeyword);
		kull_m_string_ptr_replace(&Attribute->Value, Attribute->ValueSize);
	}
	return Attribute;
}

void kull_m_crEd_attribute_delete(PKULL_M_CRED_ATTRIBUTE Attribute)
{
	if(Attribute)
	{
		if(Attribute->Keyword)
			LocalFree(Attribute->Keyword);
		if(Attribute->Value)
			LocalFree(Attribute->Value);
		LocalFree(Attribute);
	}
}

void kull_m_crEd_attribute_descr(DWORD level, PKULL_M_CRED_ATTRIBUTE Attribute)
{
	kprintf(L"%*s" L"**ATTRIBUTE**\n", level << 1, L"");
	if(Attribute)
	{
		kprintf(L"%*s" L"  Flags   : %08x - %u\n", level << 1, L"", Attribute->Flags, Attribute->Flags);
		kprintf(L"%*s" L"  Keyword : %s\n", level << 1, L"", Attribute->Keyword);
		kprintf(L"%*s" L"  Value   : ", level << 1, L"");
		kull_m_string_printSuspectUnicodeString(Attribute->Value, Attribute->ValueSize);
		kprintf(L"\n");
	}
}

PKULL_M_CRED_LEGACY_CREDS_BLOB kull_m_crEd_legacy_crEds_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_LEGACY_CREDS_BLOB crEds = NULL;
	DWORD i;
	PBYTE curPtr;
	if(crEds = (PKULL_M_CRED_LEGACY_CREDS_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_CRED_LEGACY_CREDS_BLOB)))
	{
		RtlCopyMemory(crEds, data, FIELD_OFFSET(KULL_M_CRED_LEGACY_CREDS_BLOB, __count));
		for(curPtr = (PBYTE) data + FIELD_OFFSET(KULL_M_CRED_LEGACY_CREDS_BLOB, __count); curPtr < ((PBYTE) data + crEds->structSize); curPtr += *(PDWORD) curPtr, crEds->__count++);
		if(crEds->__count)
			if(crEds->Credentials = (PKULL_M_CRED_LEGACY_CRED_BLOB *) LocalAlloc(LPTR, crEds->__count * sizeof(PKULL_M_CRED_LEGACY_CRED_BLOB)))
				for(i = 0, curPtr = (PBYTE) data + FIELD_OFFSET(KULL_M_CRED_LEGACY_CREDS_BLOB, __count); (i < crEds->__count) && (curPtr < ((PBYTE) data + crEds->structSize)); i++, curPtr += *(PDWORD) curPtr)
					crEds->Credentials[i] = kull_m_crEd_legacy_crEd_create(curPtr);
	}
	return crEds;
}

void kull_m_crEd_legacy_crEds_delete(PKULL_M_CRED_LEGACY_CREDS_BLOB crEds)
{
	DWORD i;
	if(crEds)
	{
		if(crEds->Credentials)
		{
			for(i = 0; i < crEds->__count; i++)
				kull_m_crEd_legacy_crEd_delete(crEds->Credentials[i]);
			LocalFree(crEds->Credentials);
		}
		LocalFree(crEds);
	}
}

void kull_m_crEd_legacy_crEds_descr(DWORD level, PKULL_M_CRED_LEGACY_CREDS_BLOB crEds)
{
	DWORD i;
	kprintf(L"%*s" L"**LEGACY CREDENTIALS GROUP**\n", level << 1, L"");
	if(crEds)
	{
		kprintf(L"%*s" L"  dwVersion      : %08x - %u\n", level << 1, L"", crEds->dwVersion, crEds->dwVersion);
		kprintf(L"%*s" L"  structSize     : %08x - %u\n", level << 1, L"", crEds->structSize, crEds->structSize);
		kprintf(L"%*s" L"  Credentials    : %u\n", level << 1, L"", crEds->__count);
		for(i = 0; i < crEds->__count; i++)
			kull_m_crEd_legacy_crEd_descr(level + 1, crEds->Credentials[i]);
	}
}

PKULL_M_CRED_LEGACY_CRED_BLOB kull_m_crEd_legacy_crEd_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_LEGACY_CRED_BLOB crEd = NULL;
	
	if(crEd = (PKULL_M_CRED_LEGACY_CRED_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_CRED_LEGACY_CRED_BLOB)))
	{
		RtlCopyMemory(crEd, data, FIELD_OFFSET(KULL_M_CRED_LEGACY_CRED_BLOB, TargetName));
		crEd->TargetName = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_LEGACY_CRED_BLOB, TargetName));

		crEd->dwComment = *(PDWORD) ((PBYTE) crEd->TargetName + crEd->dwTargetName);
		crEd->Comment = (LPWSTR) ((PBYTE) crEd->TargetName + crEd->dwTargetName + sizeof(DWORD));
		crEd->dwTargetAlias = *(PDWORD) ((PBYTE) crEd->Comment + crEd->dwComment);
		crEd->TargetAlias = (LPWSTR) ((PBYTE) crEd->Comment + crEd->dwComment + sizeof(DWORD));
		crEd->dwUserName = *(PDWORD) ((PBYTE) crEd->TargetAlias + crEd->dwTargetAlias);
		crEd->UserName = (LPWSTR) ((PBYTE) crEd->TargetAlias + crEd->dwTargetAlias + sizeof(DWORD));
		crEd->CredentialBlobSize = *(PDWORD) ((PBYTE) crEd->UserName + crEd->dwUserName);
		crEd->CredentialBlob = (PBYTE) crEd->UserName + crEd->dwUserName + sizeof(DWORD);
		
		if(crEd->AttributeCount)
			kull_m_crEd_attributes_create(((PBYTE) crEd->CredentialBlob + crEd->CredentialBlobSize + (crEd->CredentialBlobSize & 1)), &crEd->Attributes, crEd->AttributeCount);

		kull_m_string_ptr_replace(&crEd->TargetName, crEd->dwTargetName);
		kull_m_string_ptr_replace(&crEd->Comment, crEd->dwComment);
		kull_m_string_ptr_replace(&crEd->TargetAlias, crEd->dwTargetAlias);
		kull_m_string_ptr_replace(&crEd->UserName, crEd->dwUserName);
		kull_m_string_ptr_replace(&crEd->CredentialBlob, crEd->CredentialBlobSize);
	}
	return crEd;
}

void kull_m_crEd_legacy_crEd_delete(PKULL_M_CRED_LEGACY_CRED_BLOB crEd)
{
	if(crEd)
	{
		if(crEd->TargetName)
			LocalFree(crEd->TargetName);
		if(crEd->Comment)
			LocalFree(crEd->Comment);
		if(crEd->TargetAlias)
			LocalFree(crEd->TargetAlias);
		if(crEd->UserName)
			LocalFree(crEd->UserName);
		if(crEd->CredentialBlob)
			LocalFree(crEd->CredentialBlob);
		if(crEd->Attributes)
			kull_m_crEd_attributes_delete(crEd->Attributes, crEd->AttributeCount);
		LocalFree(crEd);
	}
}

void kull_m_crEd_legacy_crEd_descr(DWORD level, PKULL_M_CRED_LEGACY_CRED_BLOB crEd)
{
	kprintf(L"%*s" L"**LEGACY CREDENTIAL**\n", level << 1, L"");
	if(crEd)
	{
		kprintf(L"%*s" L"  crEdSize       : %08x - %u\n\n", level << 1, L"", crEd->crEdSize, crEd->crEdSize);
		kprintf(L"%*s" L"  Flags          : %08x - %u\n", level << 1, L"", crEd->Flags, crEd->Flags);
		kprintf(L"%*s" L"  Type           : %08x - %u - %s\n", level << 1, L"", crEd->Type, crEd->Type, kull_m_crEd_CredType(crEd->Type));
		kprintf(L"%*s" L"  LastWritten    : ", level << 1, L""); kull_m_string_displayFileTime(&crEd->LastWritten); kprintf(L"\n");
		kprintf(L"%*s" L"  unkFlagsOrSize : %08x - %u\n", level << 1, L"", crEd->unkFlagsOrSize, crEd->unkFlagsOrSize);
		kprintf(L"%*s" L"  Persist        : %08x - %u - %s\n", level << 1, L"", crEd->Persist, crEd->Persist, kull_m_crEd_CredPersist(crEd->Persist));
		kprintf(L"%*s" L"  AttributeCount : %08x - %u\n", level << 1, L"", crEd->AttributeCount, crEd->AttributeCount);
		kprintf(L"%*s" L"  unk0           : %08x - %u\n", level << 1, L"", crEd->unk0, crEd->unk0);
		kprintf(L"%*s" L"  unk1           : %08x - %u\n", level << 1, L"", crEd->unk1, crEd->unk1);
		kprintf(L"%*s" L"  TargetName     : %s\n", level << 1, L"", crEd->TargetName);
		kprintf(L"%*s" L"  Comment        : %s\n", level << 1, L"", crEd->Comment);
		kprintf(L"%*s" L"  TargetAlias    : %s\n", level << 1, L"", crEd->TargetAlias);
		kprintf(L"%*s" L"  UserName       : %s\n", level << 1, L"", crEd->UserName);
		kprintf(L"%*s" L"  CredentialBlob : ", level << 1, L"");
		kull_m_string_printSuspectUnicodeString(crEd->CredentialBlob, crEd->CredentialBlobSize);
		kprintf(L"\n");
		kprintf(L"%*s" L"  Attributes     : %u\n", level << 1, L"", crEd->AttributeCount);
		kull_m_crEd_attributes_descr(level + 1, crEd->Attributes, crEd->AttributeCount);
	}
}

const PCWCHAR kull_m_crEd_CredTypeToStrings[] = {
	L"?", L"generic", L"domain_password", L"domain_certificate",
	L"domain_visible_password", L"generic_certificate", L"domain_extended"
};
PCWCHAR kull_m_crEd_CredType(DWORD type)
{
	if(type >= ARRAYSIZE(kull_m_crEd_CredTypeToStrings))
		type = 0;
	return kull_m_crEd_CredTypeToStrings[type];
}

const PCWCHAR kull_m_crEd_CredPersistToStrings[] = {L"none", L"session", L"local_machine", L"enterprise"};
PCWCHAR kull_m_crEd_CredPersist(DWORD persist)
{
	if(persist < ARRAYSIZE(kull_m_crEd_CredPersistToStrings))
		return kull_m_crEd_CredPersistToStrings[persist];
	else return L"?";
}

PKULL_M_CRED_VAULT_POLICY kull_m_crEd_vAULt_policy_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_VAULT_POLICY policy = NULL;
	if(policy = (PKULL_M_CRED_VAULT_POLICY) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_POLICY)))
	{
		RtlCopyMemory(policy, data, FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, Name));
		policy->Name = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, Name));
		RtlCopyMemory(&policy->unk0, (PBYTE) policy->Name + policy->dwName, FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, key) - FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, unk0));
		policy->key = kull_m_crEd_vAULt_policy_key_create((PBYTE) policy->Name + policy->dwName +  FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, key) - FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, unk0));

		kull_m_string_ptr_replace(&policy->Name, policy->dwName);
	}
	return policy;
}

void kull_m_crEd_vAULt_policy_delete(PKULL_M_CRED_VAULT_POLICY policy)
{
	if(policy)
	{
		if(policy->Name)
			LocalFree(policy->Name);
		if(policy->key)
			kull_m_crEd_vAULt_policy_key_delete(policy->key);
		LocalFree(policy);
	}
}

void kull_m_crEd_vAULt_policy_descr(DWORD level, PKULL_M_CRED_VAULT_POLICY policy)
{
	kprintf(L"%*s" L"**VAULT POLICY**\n", level << 1, L"");
	if(policy)
	{
		kprintf(L"%*s" L"  version : %08x - %u\n", level << 1, L"", policy->version, policy->version);
		kprintf(L"%*s" L"  vAULt   : ", level << 1, L""); kull_m_string_displayGUID(&policy->vAULt); kprintf(L"\n");
		kprintf(L"%*s" L"  Name    : %s\n", level << 1, L"", policy->Name);
		kprintf(L"%*s" L"  unk0/1/2: %08x/%08x/%08x\n", level << 1, L"", policy->unk0, policy->unk1, policy->unk2);
		if(policy->key)
			kull_m_crEd_vAULt_policy_key_descr(level + 1, policy->key);
		kprintf(L"\n");
	}
}

PKULL_M_CRED_VAULT_POLICY_KEY kull_m_crEd_vAULt_policy_key_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_VAULT_POLICY_KEY key = NULL;
	if(key = (PKULL_M_CRED_VAULT_POLICY_KEY) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_POLICY_KEY)))
	{
		RtlCopyMemory(key, data, FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY_KEY, KeyBlob));
		key->KeyBlob = (PBYTE) data + FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY_KEY, KeyBlob);
		kull_m_string_ptr_replace(&key->KeyBlob, key->dwKeyBlob);
	}
	return key;
}

void kull_m_crEd_vAULt_policy_key_delete(PKULL_M_CRED_VAULT_POLICY_KEY key)
{
	if(key)
	{
		if(key->KeyBlob)
			LocalFree(key->KeyBlob);
		LocalFree(key);
	}
}

void kull_m_crEd_vAULt_policy_key_descr(DWORD level, PKULL_M_CRED_VAULT_POLICY_KEY key)
{
	kprintf(L"%*s" L"**VAULT POLICY KEY**\n", level << 1, L"");
	if(key)
	{
		kprintf(L"%*s" L"  unk0  : ", level << 1, L""); kull_m_string_displayGUID(&key->unk0); kprintf(L"\n");
		kprintf(L"%*s" L"  unk1  : ", level << 1, L""); kull_m_string_displayGUID(&key->unk1); kprintf(L"\n");
		kull_m_dPApi_blob_quick_descr(level + 1, key->KeyBlob);
		kprintf(L"\n");
	}
}

BOOL kull_m_crEd_vAULt_policy_key(PVOID data, DWORD size, BYTE aes128[AES_128_KEY_SIZE], BYTE aes256[AES_256_KEY_SIZE])
{
	BOOL status = FALSE;
	DWORD keySize128, keySize256;
	PBYTE ptr = (PBYTE) data;
	PKULL_M_CRED_VAULT_POLICY_KEY_MBDK pMbdk;
	PJlzW_BCRYPT_KEY pBcrypt;

	keySize128 = *(PDWORD) ptr;
	if(keySize128 >= 0x24)
	{
		if(*(PDWORD) (ptr + 3 * sizeof(DWORD)) == 'MBDK')
		{
			pMbdk = (PKULL_M_CRED_VAULT_POLICY_KEY_MBDK) ptr;
			if(status = ((pMbdk->type == 2) && (pMbdk->key.cbSecret == AES_128_KEY_SIZE)))
				RtlCopyMemory(aes128, pMbdk->key.data, AES_128_KEY_SIZE);
		}
		else if(*(PDWORD) (ptr + 4 * sizeof(DWORD)) == 'MSSK')
		{
			pBcrypt = (PJlzW_BCRYPT_KEY) (ptr + 3 * sizeof(DWORD));
			if(status = ((pBcrypt->bits == 128) && (pBcrypt->hardkey.cbSecret == AES_128_KEY_SIZE)))
				RtlCopyMemory(aes128, pBcrypt->hardkey.data, AES_128_KEY_SIZE);
		}

		if(status)
		{
			status = FALSE;
			ptr += sizeof(DWORD) + keySize128;
			keySize256 = *(PDWORD) ptr;
			if(keySize256 >= 0x34)
			{
				if(*(PDWORD) (ptr + 3 * sizeof(DWORD)) == 'MBDK')
				{
					pMbdk = (PKULL_M_CRED_VAULT_POLICY_KEY_MBDK) ptr;
					if(status = ((pMbdk->type == 1) && (pMbdk->key.cbSecret == AES_256_KEY_SIZE)))
						RtlCopyMemory(aes256, pMbdk->key.data, AES_256_KEY_SIZE);
				}
				else if(*(PDWORD) (ptr + 4 * sizeof(DWORD)) == 'MSSK')
				{
					pBcrypt = (PJlzW_BCRYPT_KEY) (ptr + 3 * sizeof(DWORD));
					if(status = ((pBcrypt->bits == 256) && (pBcrypt->hardkey.cbSecret == AES_256_KEY_SIZE)))
						RtlCopyMemory(aes256, pBcrypt->hardkey.data, AES_256_KEY_SIZE);
				}
			}
		}
	}
	return status;
}

PKULL_M_CRED_VAULT_CREDENTIAL kull_m_crEd_vAULt_crEdential_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_VAULT_CREDENTIAL crEdential = NULL;
	PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute;
	PBYTE ptr;
	DWORD i;
	if(crEdential = (PKULL_M_CRED_VAULT_CREDENTIAL) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_CREDENTIAL)))
	{
		RtlCopyMemory(crEdential, data, FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL, FriendlyName));
		crEdential->FriendlyName = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL, FriendlyName));
		crEdential->dwAttributesMapSize = *(PDWORD) ((PBYTE) crEdential->FriendlyName + crEdential->dwFriendlyName);
		crEdential->attributesMap = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP) ((PBYTE) crEdential->FriendlyName + crEdential->dwFriendlyName + sizeof(DWORD));

		kull_m_string_ptr_replace(&crEdential->FriendlyName, crEdential->dwFriendlyName);
		kull_m_string_ptr_replace(&crEdential->attributesMap, crEdential->dwAttributesMapSize);

		crEdential->__cbElements = crEdential->dwAttributesMapSize / sizeof(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP);
		if(crEdential->attributes = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE * ) LocalAlloc(LPTR, (crEdential->__cbElements + ((crEdential->unk0 < 4) ? 1 : 0)) * sizeof(PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE)))
		{
			for(i = 0; i < crEdential->__cbElements; i++)
			{
				if(crEdential->attributes[i] = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE)))
				{
					attribute = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE) ((PBYTE) data + crEdential->attributesMap[i].offset);

					RtlCopyMemory(crEdential->attributes[i], attribute, FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, szData));
					ptr = (PBYTE) attribute;
					if(attribute->id >= 100)
						ptr += sizeof(DWORD); // boo!
					ptr += FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, szData);
					kull_m_crEd_vAULt_crEdential_create_attribute_from_data(ptr, crEdential->attributes[i]);
				}
			}
			if(attribute && crEdential->unk0 < 4)
			{
				if(crEdential->attributes[i] = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE)))
				{
					kull_m_crEd_vAULt_crEdential_create_attribute_from_data((PBYTE) attribute + FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, data) + attribute->szData + sizeof(USHORT), crEdential->attributes[i]);
					crEdential->__cbElements++;
				}
			}
		}
	}
	return crEdential;
}

void kull_m_crEd_vAULt_crEdential_create_attribute_from_data(PBYTE ptr, PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute)
{
	BOOLEAN isIV;
	if(attribute->szData = *(PDWORD) ptr)
	{
		attribute->szData--;
		ptr += sizeof(DWORD);
		isIV = *(PBOOLEAN) ptr;
		ptr += sizeof(BOOLEAN);
		if(isIV)
		{
			attribute->szData -= sizeof(DWORD);;
			if(attribute->szIV = *(PDWORD) ptr)
			{
				attribute->szData -= attribute->szIV;
				ptr += sizeof(DWORD);
				attribute->IV = ptr;
				ptr += attribute->szIV;
				kull_m_string_ptr_replace(&attribute->IV, attribute->szIV);
			}
		}
		attribute->data = ptr;
		kull_m_string_ptr_replace(&attribute->data, attribute->szData);
	}
}

void kull_m_crEd_vAULt_crEdential_delete(PKULL_M_CRED_VAULT_CREDENTIAL crEdential)
{
	DWORD i;
	if(crEdential)
	{
		if(crEdential->FriendlyName)
			LocalFree(crEdential->FriendlyName);
		if(crEdential->attributesMap)
			LocalFree(crEdential->attributesMap);

		if(crEdential->attributes)
		{
			for(i = 0; i < crEdential->__cbElements; i++)
			{
				if(crEdential->attributes[i])
				{
					if(crEdential->attributes[i]->data)
							LocalFree(crEdential->attributes[i]->data);
					if(crEdential->attributes[i]->IV)
							LocalFree(crEdential->attributes[i]->IV);
					LocalFree(crEdential->attributes[i]);
				}
			}
			LocalFree(crEdential->attributes);
		}
		LocalFree(crEdential);
	}
}

void kull_m_crEd_vAULt_crEdential_descr(DWORD level, PKULL_M_CRED_VAULT_CREDENTIAL crEdential)
{
	DWORD i;
	kprintf(L"%*s" L"**VAULT CREDENTIAL**\n", level << 1, L"");
	if(crEdential)
	{
		kprintf(L"%*s" L"  SchemaId            : ", level << 1, L""); kull_m_string_displayGUID(&crEdential->SchemaId); kprintf(L"\n");
		kprintf(L"%*s" L"  unk0                : %08x - %u\n", level << 1, L"", crEdential->unk0, crEdential->unk0);
		kprintf(L"%*s" L"  LastWritten         : ", level << 1, L""); kull_m_string_displayFileTime(&crEdential->LastWritten); kprintf(L"\n");
		kprintf(L"%*s" L"  unk1                : %08x - %u\n", level << 1, L"", crEdential->unk1, crEdential->unk1);
		kprintf(L"%*s" L"  unk2                : %08x - %u\n", level << 1, L"", crEdential->unk2, crEdential->unk2);
		kprintf(L"%*s" L"  FriendlyName        : %s\n", level << 1, L"", crEdential->FriendlyName);
		kprintf(L"%*s" L"  dwAttributesMapSize : %08x - %u\n", level << 1, L"", crEdential->dwAttributesMapSize, crEdential->dwAttributesMapSize);
		for(i = 0; i < (crEdential->dwAttributesMapSize / sizeof(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP)); i++)
			kprintf(L"%*s" L"  * Attribute %3u @ offset %08x - %u  (unk %08x - %u)\n", level << 1, L"", crEdential->attributesMap[i].id, crEdential->attributesMap[i].offset, crEdential->attributesMap[i].offset, crEdential->attributesMap[i].unk, crEdential->attributesMap[i].unk);
		for(i = 0; i < crEdential->__cbElements; i++)
			kull_m_crEd_vAULt_crEdential_attribute_descr(level + 1, crEdential->attributes[i]);
		kprintf(L"\n");
	}
}

void kull_m_crEd_vAULt_crEdential_attribute_descr(DWORD level, PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute)
{
	kprintf(L"%*s" L"**VAULT CREDENTIAL ATTRIBUTE**\n", level << 1, L"");
	if(attribute)
	{
		kprintf(L"%*s" L"  id      : %08x - %u\n", level << 1, L"", attribute->id, attribute->id);
		kprintf(L"%*s" L"  unk0/1/2: %08x/%08x/%08x\n", level << 1, L"", attribute->unk0, attribute->unk1, attribute->unk2);
		if(attribute->szIV && attribute->IV)
		{
			kprintf(L"%*s" L"  IV      : ", level << 1, L"");
			kull_m_string_wprintf_hex(attribute->IV, attribute->szIV, 0);
			kprintf(L"\n");
		}
		if(attribute->szData && attribute->data)
		{
			kprintf(L"%*s" L"  Data    : ", level << 1, L"");
			kull_m_string_wprintf_hex(attribute->data, attribute->szData, 0);
			kprintf(L"\n");
		}
	}
}

PKULL_M_CRED_VAULT_CLEAR kull_m_crEd_vAULt_clear_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_VAULT_CLEAR clear = NULL;
	DWORD i, size;
	PBYTE ptr;
	if(clear = (PKULL_M_CRED_VAULT_CLEAR) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_CLEAR)))
	{
		RtlCopyMemory(clear, data, FIELD_OFFSET(KULL_M_CRED_VAULT_CLEAR, entries));
		if(clear->count && (clear->entries = (PKULL_M_CRED_VAULT_CLEAR_ENTRY *) LocalAlloc(LPTR, clear->count * sizeof(PKULL_M_CRED_VAULT_CLEAR_ENTRY))))
		{
			ptr = (PBYTE) data + FIELD_OFFSET(KULL_M_CRED_VAULT_CLEAR, entries);
			for(i = 0; i < clear->count; i++)
			{
				size = FIELD_OFFSET(KULL_M_CRED_VAULT_CLEAR_ENTRY, data) + *(PDWORD) (ptr + FIELD_OFFSET(KULL_M_CRED_VAULT_CLEAR_ENTRY, size));
				if(clear->entries[i] = (PKULL_M_CRED_VAULT_CLEAR_ENTRY) LocalAlloc(LPTR, size))
					RtlCopyMemory(clear->entries[i], ptr, size);
				ptr += size;
			}
		}
	}
	return clear;
}

void kull_m_crEd_vAULt_clear_delete(PKULL_M_CRED_VAULT_CLEAR clear)
{
	DWORD i;
	if(clear)
	{
		if(clear->entries)
		{
			for(i = 0 ; i < clear->count; i++)
				if(clear->entries[i])
					LocalFree(clear->entries[i]);
			LocalFree(clear->entries);
		}
		LocalFree(clear);
	}
}

void kull_m_crEd_vAULt_clear_descr(DWORD level, PKULL_M_CRED_VAULT_CLEAR clear)
{
	DWORD i;
	kprintf(L"%*s" L"**VAULT CREDENTIAL CLEAR ATTRIBUTES**\n", level << 1, L"");
	if(clear)
	{
		kprintf(L"%*s" L"  version: %08x - %u\n", level << 1, L"", clear->version, clear->version);
		kprintf(L"%*s" L"  count  : %08x - %u\n", level << 1, L"", clear->count, clear->count);
		kprintf(L"%*s" L"  unk    : %08x - %u\n", level << 1, L"", clear->unk, clear->unk);
		if(clear->entries)
		{
			kprintf(L"\n");
			for(i = 0; i < clear->count; i++)
			{
				kprintf(L"%*s" L"  * ", level << 1, L"");
				switch(clear->entries[i]->id)
				{
				case 1:
					kprintf(L"ressource     : ");
					break;
				case 2:
					kprintf(L"identity      : ");
					break;
				case 3:
					kprintf(L"authenticator : ");
					break;
				default:
					kprintf(L"property %3u  : ", clear->entries[i]->id);
					break;
				}
				kull_m_string_printSuspectUnicodeString(clear->entries[i]->data, clear->entries[i]->size);
				kprintf(L"\n");
			}
		}
	}
}