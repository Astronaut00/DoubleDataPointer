#pragma once
#include "stdafx.h"

namespace Core {
	PVOID GetSystemModuleBase(LPCSTR moduleName);


	//Sketch
	ULONG_PTR GetKernelDirBase();
	ULONG_PTR GetProcessCr3(PEPROCESS pProcess);
	NTSTATUS ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written);

	//Safe Guarded Calls
	NTSTATUS GetModuleBaseAddress(int processId, const char* moduleName, uint64_t* baseAddress);
	NTSTATUS GetProcessBaseAddress(int pid, uint64_t* Address);
	NTSTATUS ReadProcessMemory(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteProcessMemory(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* written);


	ULONG_PTR GetKernelDirBase();
}