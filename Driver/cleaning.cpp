#include "cleaning.h"
#include "util.h"

NTSTATUS NullPageFrameNumbersFromMdl(PMDL mdl)
{
	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	if (!mdl_pages) { return STATUS_UNSUCCESSFUL; }

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG null_pfn = 0x0;
	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		MmCopyMemory(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}
	return STATUS_SUCCESS;
}

NTSTATUS Cleaning::NullPageFrameNumbers(uint64_t start, uint32_t size)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PMDL mdl = IoAllocateMdl((PVOID)start, (ULONG)size, FALSE, FALSE, NULL);

	if (!mdl)
	{
		printf("[mapper] Failed to allocate Mdl\n");
		return status;
	}

	status = NullPageFrameNumbersFromMdl(mdl);

	IoFreeMdl(mdl);

	return status;
}

PVOID resolve_relative_address(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize) //lol paste you got me. IDK the pointers were fucked up somewhere and I'm too lazy to go and manually reread it.
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

NTSTATUS FindBigPoolTable(uint64_t* pPoolBigPageTable, uint64_t* pPoolBigPageTableSize)
{
	PVOID ntoskrnl = Core::GetSystemModuleBase("\\SystemRoot\\system32\\ntoskrnl.exe");

	if (!ntoskrnl)
	{
		printf("[mapper] Failed to get ntoskrnl.exe base Address!\n");
		return STATUS_UNSUCCESSFUL;
	}
	printf("[mapper] ntoskrnl.exe -> 0x%p\n", ntoskrnl);

	PVOID ExProtectPoolExCallInstructionsAddress = (PVOID)Util::FindPattern(ntoskrnl, "\xE8\x00\x00\x00\x00\x83\x67\x0C\x00", "x????xxxx");

	PVOID ExProtectPoolExAddress = resolve_relative_address(ExProtectPoolExCallInstructionsAddress, 1, 5);

	if (!ExProtectPoolExAddress)
		return false;

	PVOID PoolBigPageTableInstructionAddress = (PVOID)((ULONG64)ExProtectPoolExAddress + 0x95);
	*pPoolBigPageTable = (UINT64)resolve_relative_address(PoolBigPageTableInstructionAddress, 3, 7);

	PVOID PoolBigPageTableSizeInstructionAddress = (PVOID)((ULONG64)ExProtectPoolExAddress + 0x8E);
	*pPoolBigPageTableSize = (UINT64)resolve_relative_address(PoolBigPageTableSizeInstructionAddress, 3, 7);

	return STATUS_SUCCESS;
}

NTSTATUS Cleaning::CleanFromBigPools(uint64_t start)
{
	uint64_t pPoolBigPageTable = 0;
	uint64_t pPoolBigPageTableSize = 0;

	if (NT_SUCCESS(FindBigPoolTable(&pPoolBigPageTable, &pPoolBigPageTableSize)))
	{
		PPOOL_TRACKER_BIG_PAGES PoolBigPageTable = 0;
		RtlCopyMemory(&PoolBigPageTable, (PVOID)pPoolBigPageTable, 8);
		SIZE_T PoolBigPageTableSize = 0;
		RtlCopyMemory(&PoolBigPageTableSize, (PVOID)pPoolBigPageTableSize, 8);

		for (int i = 0; i < PoolBigPageTableSize; i++)
		{
			if (PoolBigPageTable[i].Va == start || PoolBigPageTable[i].Va == (start + 0x1))
			{
				PoolBigPageTable[i].Va = 0x1;
				PoolBigPageTable[i].NumberOfBytes = 0x0;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_UNSUCCESSFUL;
}
