#pragma once
#include "stdafx.h"
#include "cleaning.h"

//these things need thier own file hooks.h and hooks.cpp
PVOID(__fastcall* oApiSetEditionSetProcessWindowStationEntryPointPointer)(PVOID);
PVOID(__fastcall* oApiSetEnsurePointerDeviceHasMonitorPointer)(PVOID);

/* 
  * FOR CHAINING: 
  *	ApiSetEnsurePointerDeviceHasMonitor(PDEVICE_OBJECT a1)
  * sig: \xE8\x00\x00\x00\x00\x85\xC0\x75\x43, x????xxxx (RVA 5)
  *		qword offset: (+0x78) (RVA 7)
  *		qword_1C0258DD0(PDEVICE_OBJECT)
  *
  * FOR USERMODE CALL:
  * __int64 __fastcall NtUserSetProcessWindowStation(struct _DEVICE_OBJECT *a1)
  * 
  * ApiSetEditionSetProcessWindowStationEntryPoint(PDEVICE_OBJECT)
  * sig: \xE8\x00\x00\x00\x00\x48\x98\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10, x????xxxxxxxxxxxxxxxxxxxxxxxxxx
  *		qword offset: (+0x5E) (RVA 7)
  *		qword_1C0258DD0(PDEVICE_OBJECT)
  *
*/


PVOID ApiSetEnsurePointerDeviceHasMonitorHook(PDEVICE_OBJECT DeviceObject) 
{

#pragma region Validation
	{
		if (ExGetPreviousMode() != UserMode) {
			return oApiSetEditionSetProcessWindowStationEntryPointPointer(DeviceObject);
		}

		Communication comm = {};
		size_t read;


		if (!NT_SUCCESS(Core::ReadVirtual(Core::GetKernelDirBase(), (uint64_t)DeviceObject, (uint8_t*)&comm, sizeof(Communication), &read)) || comm.key != COMMUNICATION_KEY) {
			printf("[mapper] Invalid Usermode Call\n");
			return oApiSetEditionSetProcessWindowStationEntryPointPointer(DeviceObject);
		}
	}
#pragma endregion

	auto comm = (Communication*)DeviceObject;

	printf("[mapper] called w reason -> 0x%p\n", comm->key);
	printf("[mapper] called w request -> 0x%p\n", comm->request);

	switch (comm->request) 
	{
		case Request::READPROCESSMEMORY: 
		{
			if (!NT_SUCCESS(Core::ReadProcessMemory(comm->processID,
				comm->address,
				comm->buffer,
				comm->size,
				&comm->read)))
			{
				printf("[mapper] failed a read to -> 0x%llx\n", comm->address);
			}

		} break;
		case Request::WRITEPROCESSMEMORY:
		{

			if (!NT_SUCCESS(Core::WriteProcessMemory(comm->processID,
				comm->address,
				comm->buffer,
				comm->size,
				&comm->written)))
			{
				printf("[mapper] failed a write to -> 0x%llx\n", comm->address);
			};
		} break;
		case Request::GETMODULEBASE:
		{
			printf("comm->processID: %d, comm->moduleName: %s\n", comm->processID, comm->moduleName);
			uint64_t baseAddress = NULL;
			if (NT_SUCCESS(Core::GetModuleBaseAddress(comm->processID, comm->moduleName, &baseAddress)))
				comm->buffer = (uint64_t)baseAddress;
			else
				printf("[mapper] failed to find %s in %d\n", comm->moduleName, comm->processID);
		} break;
		case Request::GETBASE:
		{
			uint64_t baseAddress = NULL;
			if (NT_SUCCESS(Core::GetProcessBaseAddress(comm->processID, &baseAddress)))
				comm->buffer = (uint64_t)baseAddress;
			else
				printf("[mapper] process id: %d base: %p", comm->processID, baseAddress);
		} break;
		//we need a command to restore the original pointers, AND THATS ALL.
	}
	return NULL;
}

void* GetFunctionDataPointer(void* FunctionAddress, uint64_t DataPointerOffset)
{

	return 0;
}

void CleanTraces(EntryParams* params)
{
	uint64_t entryPoint = params->entryPoint;
	uint32_t poolBase = params->poolBase;
	uint32_t size = params->size;

	if (NT_SUCCESS(Cleaning::NullPageFrameNumbers(poolBase, size)))
		printf("[mapper] Nulled Page Frame Number\n");
	else
		printf("[mapper] Failed to Null Page Frame Numbers\n");

	if (NT_SUCCESS(Cleaning::CleanFromBigPools(params->poolBase)))
		printf("[mapper] Cleaned from Bigpools\n");
	else
		printf("[mapper] Failed to clean from Bigpools\n");
}


NTSTATUS DriverEntry(EntryParams* params) //damn this needs serious fixing... it's clunky
{
	if (!params)
		return STATUS_FAILED_DRIVER_ENTRY;

	printf("[mapper] Driver Entry: %xll Image Base: %xll Size: %xll\n", params->entryPoint, params->poolBase, params->size);

#pragma region win32base.sys
	auto win32kbase = Core::GetSystemModuleBase("\\SystemRoot\\System32\\win32kbase.sys");
	{

		if (!win32kbase) 
		{
			printf("[mapper] Failed to get Base Address!\n");
			return STATUS_FAILED_DRIVER_ENTRY;
		}

		printf("[mapper] win32kbase.sys -> 0x%p\n", win32kbase);
	}
#pragma endregion
#pragma region ApiSetEditionSetProcessWindowStationEntryPoint

	auto ApiSetEditionSetProcessWindowStationEntryPointAddress = Util::FindPattern(
		win32kbase, 
		"\xE8\x00\x00\x00\x00\x48\x98\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10", 
		"x????xxxxxxxxxxxxxxxxxxxxxxxxxx");
	{
		if (!ApiSetEditionSetProcessWindowStationEntryPointAddress)
		{
			printf("[mapper] Unable to find ApiSetEditionSetProcessWindowStationEntryPoint signature!\n");
			return STATUS_FAILED_DRIVER_ENTRY;
		}
		ApiSetEditionSetProcessWindowStationEntryPointAddress = RVA(ApiSetEditionSetProcessWindowStationEntryPointAddress, 5);
		printf("[mapper] ApiSetEditionSetProcessWindowStationEntryPoint -> 0x%p\n", ApiSetEditionSetProcessWindowStationEntryPointAddress);
	}

	auto ApiSetEditionSetProcessWindowStationEntryPointDataPointer = RVA(ApiSetEditionSetProcessWindowStationEntryPointAddress + 0x5E, 7);
	{
		if (!ApiSetEditionSetProcessWindowStationEntryPointDataPointer)
		{
			printf("[mapper] Invalid ApiSetEditionSetProcessWindowStationEntryPoint Data Pointer!\n");
			return STATUS_FAILED_DRIVER_ENTRY;
		}
		printf("[mapper] ApiSetEditionSetProcessWindowStationEntryPoint Data Pointer -> 0x%p\n", 
			ApiSetEditionSetProcessWindowStationEntryPointAddress);
	}
#pragma endregion
#pragma region ApiSetEnsurePointerDeviceHasMonitor
	auto ApiSetEnsurePointerDeviceHasMonitorAddress = Util::FindPattern(win32kbase, "\xE8\x00\x00\x00\x00\x85\xC0\x75\x43", "x????xxxx");
	{
		if (!ApiSetEnsurePointerDeviceHasMonitorAddress) 
		{
			printf("[mapper] Unable to find ApiSetEnsurePointerDeviceHasMonitor signature!\n");
			return STATUS_FAILED_DRIVER_ENTRY;
		}
		ApiSetEnsurePointerDeviceHasMonitorAddress = RVA(ApiSetEnsurePointerDeviceHasMonitorAddress, 5);
		printf("[mapper] ApiSetEnsurePointerDeviceHasMonitor -> 0x%p\n", ApiSetEnsurePointerDeviceHasMonitorAddress);
	}

	auto ApiSetEnsurePointerDeviceHasMonitorDataPointer = RVA(ApiSetEnsurePointerDeviceHasMonitorAddress + 0x78, 7);
	{
		if (!ApiSetEnsurePointerDeviceHasMonitorDataPointer) 
		{
			printf("[mapper] Invalid ApiSetEnsurePointerDeviceHasMonitor Data Pointer!\n");
			return STATUS_FAILED_DRIVER_ENTRY;
		}
		printf("[mapper] ApiSetEnsurePointerDeviceHasMonitor Data Pointer -> 0x%p\n", ApiSetEnsurePointerDeviceHasMonitorDataPointer);
	}

#pragma endregion
#pragma region PointerSwapping
	{
		*(PVOID*)&oApiSetEnsurePointerDeviceHasMonitorPointer = InterlockedExchangePointer(
				(volatile PVOID*)ApiSetEnsurePointerDeviceHasMonitorDataPointer,
				ApiSetEnsurePointerDeviceHasMonitorHook);

		printf("[mapper] swapped pointer -> 0x%p to 0x%p\n", 
			ApiSetEnsurePointerDeviceHasMonitorDataPointer, ApiSetEnsurePointerDeviceHasMonitorHook);
	}

	{
		*(PVOID*)&oApiSetEditionSetProcessWindowStationEntryPointPointer = InterlockedExchangePointer(
				(volatile PVOID*)ApiSetEditionSetProcessWindowStationEntryPointDataPointer,
				ApiSetEnsurePointerDeviceHasMonitorAddress);

		printf("[mapper] swapped pointer -> 0x%p to 0x%p\n", 
			ApiSetEditionSetProcessWindowStationEntryPointDataPointer, ApiSetEnsurePointerDeviceHasMonitorAddress);
	}

#pragma endregion


	CleanTraces(params); //This should be NTSTATUS

	return STATUS_SUCCESS;
}
