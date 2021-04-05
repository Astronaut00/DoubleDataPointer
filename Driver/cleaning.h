#pragma once
#include "stdafx.h"

namespace Cleaning
{
	NTSTATUS NullPageFrameNumbers(uint64_t start, uint32_t size);
	NTSTATUS CleanFromBigPools(uint64_t start);
}