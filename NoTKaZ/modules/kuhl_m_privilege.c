/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kuhl_m_PRIViLeGe.h"

const KUHL_M_C kuhl_m_c_PRIViLeGe[] = {
	{kuhl_m_PRIViLeGe_debug,		L"debug",		L"Ask debug PRIViLeGe"},
	{kuhl_m_PRIViLeGe_driver,		L"driver",		L"Ask load driver PRIViLeGe"},
	{kuhl_m_PRIViLeGe_security,		L"security",	L"Ask security PRIViLeGe"},
	{kuhl_m_PRIViLeGe_tcb,			L"tcb",			L"Ask tcb PRIViLeGe"},
	{kuhl_m_PRIViLeGe_backup,		L"backup",		L"Ask backup PRIViLeGe"},
	{kuhl_m_PRIViLeGe_restore,		L"restore",		L"Ask restore PRIViLeGe"},
	{kuhl_m_PRIViLeGe_sysenv,		L"sysenv",		L"Ask system environment PRIViLeGe"},

	{kuhl_m_PRIViLeGe_id,			L"id",			L"Ask a PRIViLeGe by its id"},
	{kuhl_m_PRIViLeGe_name,			L"name",		L"Ask a PRIViLeGe by its name"},
};

const KUHL_M kuhl_m_PRIViLeGe = {
	L"PRIViLeGe", L"Privilege module", NULL,
	ARRAYSIZE(kuhl_m_c_PRIViLeGe), kuhl_m_c_PRIViLeGe, NULL, NULL
};

NTSTATUS kuhl_m_PRIViLeGe_simple(ULONG privId)
{
	ULONG previousState;
	NTSTATUS status = RtlAdjustPrivilege(privId, TRUE, FALSE, &previousState);
	if(NT_SUCCESS(status))
		kprintf(L"Privilege \'%u\' OK\n", privId);
	else PRINT_ERROR(L"RtlAdjustPrivilege (%u) %08x\n", privId, status);
	return status;
}

NTSTATUS kuhl_m_PRIViLeGe_id(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	if(argc)
		status = kuhl_m_PRIViLeGe_simple(wcstoul(argv[0], NULL, 0));
	else PRINT_ERROR(L"Missing \'id\'\n");
	return status;
}

NTSTATUS kuhl_m_PRIViLeGe_name(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	LUID luid;
	if(argc)
	{
		if(LookupPrivilegeValue(NULL, argv[0], &luid))
		{
			if(!luid.HighPart)
				status = kuhl_m_PRIViLeGe_simple(luid.LowPart);
			else PRINT_ERROR(L"LUID high part is %u\n", luid.HighPart);
		}
		else PRINT_ERROR_AUTO(L"LookupPrivilegeValue");
	}
	else PRINT_ERROR(L"Missing \'name\'\n");
	return status;
}

NTSTATUS kuhl_m_PRIViLeGe_debug(int argc, wchar_t * argv[])
{
	return kuhl_m_PRIViLeGe_simple(SE_DEBUG);
}

NTSTATUS kuhl_m_PRIViLeGe_driver(int argc, wchar_t * argv[])
{
	return kuhl_m_PRIViLeGe_simple(SE_LOAD_DRIVER);
}

NTSTATUS kuhl_m_PRIViLeGe_security(int argc, wchar_t * argv[])
{
	return kuhl_m_PRIViLeGe_simple(SE_SECURITY);
}

NTSTATUS kuhl_m_PRIViLeGe_tcb(int argc, wchar_t * argv[])
{
	return kuhl_m_PRIViLeGe_simple(SE_TCB);
}
NTSTATUS kuhl_m_PRIViLeGe_backup(int argc, wchar_t * argv[])
{
	return kuhl_m_PRIViLeGe_simple(SE_BACKUP);
}

NTSTATUS kuhl_m_PRIViLeGe_restore(int argc, wchar_t * argv[])
{
	return kuhl_m_PRIViLeGe_simple(SE_RESTORE);
}

NTSTATUS kuhl_m_PRIViLeGe_sysenv(int argc, wchar_t * argv[])
{
	return kuhl_m_PRIViLeGe_simple(SE_SYSTEM_ENVIRONMENT);
}