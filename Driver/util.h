#pragma once
#include "stdafx.h"


//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

namespace Util {

	PIMAGE_NT_HEADERS getHeader(PVOID module);
	PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask);
}