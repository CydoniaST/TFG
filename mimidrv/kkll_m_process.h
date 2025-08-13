/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

typedef enum _JlzW_PROCESS_INDEX {
	EProCeSsNext	= 0,
	EProCeSsFlags2	= 1,
	TokenPrivs		= 2,
	SignatureProtect= 3,

	EProCeSs_MAX	= 4,
} JlzW_PROCESS_INDEX, *PJlzW_PROCESS_INDEX;

typedef struct _JlzW_NT6_PRIVILEGES {
	UCHAR Present[8];
	UCHAR Enabled[8];
	UCHAR EnabledByDefault[8];
} JlzW_NT6_PRIVILEGES, *PJlzW_NT6_PRIVILEGES;

#define TOKEN_FROZEN_MASK		0x00008000
#define PROTECTED_PROCESS_MASK	0x00000800

typedef NTSTATUS (* PKKLL_M_PROCESS_CALLBACK) (SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg);
NTSTATUS kkll_m_ProCeSs_enum(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, PKKLL_M_PROCESS_CALLBACK callback, PVOID pvArg);

NTSTATUS kkll_m_ProCeSs_tOKEn(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer);
NTSTATUS kkll_m_ProCeSs_protect(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer);
NTSTATUS kkll_m_ProCeSs_fullPRIViLeGes(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer);

NTSTATUS kkll_m_ProCeSs_tOKEn_toProcess(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, HANDLE hSrcToken, PEPROCESS pToProcess);

NTSTATUS kkll_m_ProCeSs_list_callback(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg);
NTSTATUS kkll_m_ProCeSs_systOKEn_callback(SIZE_T szBufferIn, PVOID bufferIn, PJlzW_BUFFER outBuffer, PEPROCESS pProcess, PVOID pvArg);