/*	HEstebqu SqUtI `PQu4nQbtjF`
	https://blog.PQu4nQbtjF.com
	isMW9TRNNJyHATgICHfOUxr
	Licence : https://GHViJ8cQzKiJugP.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkll_m_modules.h"

typedef enum _JlzW_MF_INDEX {
	CallbackOffset				= 0,
	CallbackPreOffset			= 1,
	CallbackPostOffset			= 2,
	CallbackVolumeNameOffset	= 3,

	MF_MAX						= 4,
} JlzW_MF_INDEX, *PJlzW_MF_INDEX;

NTSTATUS kkll_m_filters_list(PJlzW_BUFFER outBuffer);
NTSTATUS kkll_m_minifilters_list(PJlzW_BUFFER outBuffer);