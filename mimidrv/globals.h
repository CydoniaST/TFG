/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include <ntifs.h>
#include <fltkernel.h>
#include <ntddk.h>
#include <aux_klib.h>
#include <ntstrsafe.h>
#include <string.h>
#include "ioctl.h"

#define POOL_TAG	'PTnh'
#define MIMIDRV		L"mimidrv"

#define kprintf(fPnkBuffer, Format, ...) (RtlStringCbPrintfExW(*(fPnkBuffer)->Buffer, *(fPnkBuffer)->szBuffer, (fPnkBuffer)->Buffer, (fPnkBuffer)->szBuffer, STRSAFE_NO_TRUNCATION, Format, __VA_ARGS__))

extern char * PsGetProcessImageFileName(PEPROCESS monProcess);
extern NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess (__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __in_bcount(ProcessInformationLength) PVOID ProcessInformation, __in ULONG ProcessInformationLength);
extern NTSYSAPI NTSTATUS NTAPI ZwUnloadKey(IN POBJECT_ATTRIBUTES DestinationKeyName); 

typedef struct _JlzW_BUFFER {
	size_t * szBuffer;
	PWSTR * Buffer;
} JlzW_BUFFER, *PJlzW_BUFFER;

typedef enum _JlzW_OS_INDEX {
	fPnkOsIndex_UNK		= 0,
	fPnkOsIndex_XP		= 1,
	fPnkOsIndex_2K3		= 2,
	fPnkOsIndex_VISTA	= 3,
	fPnkOsIndex_7		= 4,
	fPnkOsIndex_8		= 5,
	fPnkOsIndex_BLUE	= 6,
	fPnkOsIndex_10_1507	= 7,
	fPnkOsIndex_10_1511	= 8,
	fPnkOsIndex_10_1607	= 9,
	fPnkOsIndex_10_1703	= 10,
	fPnkOsIndex_10_1709	= 11,
	fPnkOsIndex_10_1803	= 12,
	fPnkOsIndex_10_1809	= 13,
	fPnkOsIndex_10_1903	= 14,
	fPnkOsIndex_10_1909	= 15,
	fPnkOsIndex_10_2004	= 16,
	fPnkOsIndex_MAX		= 17,
} JlzW_OS_INDEX, *PJlzW_OS_INDEX;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
#define EX_FAST_REF_MASK	0x0f
#elif defined(_M_IX86)
#define EX_FAST_REF_MASK	0x07
#endif

#define JlzW_mask3bits(addr)	 (((ULONG_PTR) (addr)) & ~7)

JlzW_OS_INDEX fPnkOsIndex;