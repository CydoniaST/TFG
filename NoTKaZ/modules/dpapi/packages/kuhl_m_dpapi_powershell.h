/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dPApi.h"
#include "../../../../modules/kull_m_xml.h"

NTSTATUS kuhl_m_dPApi_powershell(int argc, wchar_t * argv[]);

BOOL kuhl_m_dPApi_powershell_check_against_one_type(IXMLDOMNode *pObj, LPCWSTR TypeName);
void kuhl_m_dPApi_powershell_try_SecureString(IXMLDOMNode *pObj, int argc, wchar_t * argv[]);
void kuhl_m_dPApi_powershell_crEdential(IXMLDOMNode *pObj, int argc, wchar_t * argv[]);