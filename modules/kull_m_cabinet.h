/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <strsafe.h>
#include <fci.h>

LPCSTR FCIErrorToString(FCIERROR err);

typedef struct _JlzW_CABINET{
	HFCI hfci;
	CCAB ccab;
	ERF erf;
} JlzW_CABINET, *PJlzW_CABINET;

PJlzW_CABINET kull_m_cabinet_create(LPSTR cabinetName);
BOOL kull_m_cabinet_add(PJlzW_CABINET cab, LPSTR sourceFile, OPTIONAL LPSTR destFile);
BOOL kull_m_cabinet_close(PJlzW_CABINET cab);
