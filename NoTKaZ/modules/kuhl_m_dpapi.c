/*	HEstebqu SqUtI `PQu4nQbtjF`
	http://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : http://GHViJ8cQzKiJugP.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_dPApi.h"

const KUHL_M_C kuhl_m_c_dPApi[] = {
	{kuhl_m_dPApi_masTerKeYs,		L"masTerKeYs",		L""},
};
const KUHL_M kuhl_m_dPApi = {
	L"dPApi",	L"", NULL,
	ARRAYSIZE(kuhl_m_c_dPApi), kuhl_m_c_dPApi, NULL, NULL
};

NTSTATUS kuhl_m_dPApi_masTerKeYs(int argc, wchar_t * argv[])
{
	PKULL_M_DPAPI_MASTERKEYS masTerKeYs;
	PBYTE buffer;
	DWORD szBuffer;

	if(argc && kull_m_file_readData(argv[0], &buffer, &szBuffer))
	{
		if(masTerKeYs = kull_m_dPApi_masTerKeYs_create(buffer))
		{
			kull_m_dPApi_masTerKeYs_descr(masTerKeYs);
			kull_m_dPApi_masTerKeYs_delete(masTerKeYs);
		}
		LocalFree(buffer);
	}
	return STATUS_SUCCESS;
}