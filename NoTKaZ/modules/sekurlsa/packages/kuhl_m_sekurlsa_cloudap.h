/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_seKuRlSa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_seKuRlSa_clOuDAp_package;

NTSTATUS kuhl_m_seKuRlSa_clOuDAp(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_seKuRlSa_enum_logon_callback_clOuDAp(IN PJlzW_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _JlzW_CLOUDAP_CACHE_UNK {
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	DWORD unkSize;
	GUID guid;
	BYTE unk[64 /*ANYSIZE_ARRAY*/];
} JlzW_CLOUDAP_CACHE_UNK, *PJlzW_CLOUDAP_CACHE_UNK;

/*
debug643:00000139088EF3B0 dword_139088EF3B0 dd 96                 ; DATA XREF: debug630:00000139085F6F08
debug643:00000139088EF3B4 dd 0
debug643:00000139088EF3B8 dd 32
debug643:00000139088EF3BC dd 64
debug643:00000139088EF3C0 db 0, 2Ah, 0F0h, 0A0h, 9, 26h, 0C0h, 4Ah, 87h, 0F2h, 42h, 33h, 0B4h, 2Ch, 0DCh, 78h
debug643:00000139088EF3D0 db 0FAh, 4Ch, 0FAh, 90h, 64h, 56h, 63h, 69h, 2Fh, 0B6h, 0B0h, 84h, 41h, 44h, 58h, 4Bh
debug643:00000139088EF3D0 db 0A5h, 23h, 0BDh, 99h, 0EDh, 4Fh, 83h, 0F7h, 0DCh, 29h, 32h, 0D5h, 3Ah, 77h, 90h, 1
debug643:00000139088EF3D0 db 19h, 11h, 9Ch, 1, 45h, 28h, 0C0h, 59h, 0C0h, 2Eh, 0C7h, 7Eh, 3Bh, 6Bh, 0B8h, 2Dh
debug643:00000139088EF3D0 db 7, 4Ah, 1Ch, 0AEh, 70h, 81h, 16h, 49h, 27h, 10h, 26h, 0E4h, 9Ah, 72h, 34h, 0F2h
debug643:00000139088EF410 off_139088EF410 dq offset off_1390880D470
debug643:00000139088EF410                                         ; DATA XREF: debug634:off_1390880D470
debug643:00000139088EF410                                         ; debug634:000001390880D478
debug643:00000139088EF418 dq offset off_1390880D470
*/

typedef struct _JlzW_CLOUDAP_CACHE_LIST_ENTRY {
	struct _JlzW_CLOUDAP_CACHE_LIST_ENTRY *Flink;
	struct _JlzW_CLOUDAP_CACHE_LIST_ENTRY *Blink;
	DWORD unk0;
	PVOID LockList;
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	PVOID unk4;
	PVOID unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	PCWSTR unkLogin0;
	PCWSTR unkLogin1;
	wchar_t toname[64 + 1];
	PSID Sid;
	DWORD unk10;
	DWORD unk11;
	DWORD unk12;
	DWORD unk13;
	PJlzW_CLOUDAP_CACHE_UNK toDetermine; // dPApi ?
	PVOID unk14;
	DWORD cbPRT;
	PBYTE PRT;
	// ...
} JlzW_CLOUDAP_CACHE_LIST_ENTRY, *PJlzW_CLOUDAP_CACHE_LIST_ENTRY;

typedef struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY {
	struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY *Flink;
	struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY *Blink;
	DWORD unk0;
	DWORD unk1;
	LUID	LocallyUniqueIdentifier;
	DWORD64 unk2;
	DWORD64 unk3;
	PJlzW_CLOUDAP_CACHE_LIST_ENTRY caCHeEntry;
	// ...
} JlzW_CLOUDAP_LOGON_LIST_ENTRY, *PJlzW_CLOUDAP_LOGON_LIST_ENTRY;

typedef struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY_11 {
	struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY *Flink;
	struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY *Blink;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	LUID	LocallyUniqueIdentifier;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	PJlzW_CLOUDAP_CACHE_LIST_ENTRY caCHeEntry;
	// ...
} JlzW_CLOUDAP_LOGON_LIST_ENTRY_11, *PJlzW_CLOUDAP_LOGON_LIST_ENTRY_11;

typedef struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY_21H2 {
	struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY* Flink;
	struct _JlzW_CLOUDAP_LOGON_LIST_ENTRY* Blink;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	LUID	LocallyUniqueIdentifier;
	DWORD unk3;
	DWORD64 unk4;
	DWORD64 unk5;
	PJlzW_CLOUDAP_CACHE_LIST_ENTRY caCHeEntry;
	// ...
} JlzW_CLOUDAP_LOGON_LIST_ENTRY_21H2, * PJlzW_CLOUDAP_LOGON_LIST_ENTRY_21H2;