#pragma once
#include "memory.h"

/*
* __int64 __fastcall NtUserSetProcessWindowStation(struct _DEVICE_OBJECT *a1)
*/
static NTSTATUS(*NtUserCloseWindowStation)(PVOID a1) = nullptr;


Memory::Memory(int32_t pid, std::vector<std::string> moduleNames)
{
	LoadLibraryA("user32.dll");
	Setup("NtUserSetProcessWindowStation");

	processId = pid;

	for (const auto & moduleName : moduleNames)
	{
		uint64_t baseAddress = NULL;
		if (GetModuleBaseAddressFromKernel(processId, moduleName.c_str(), &baseAddress))
			moduleBases.at(moduleName) = baseAddress;
			
	}

	GetProcessBaseAddressFromKernel(pid, &this->base);
}

bool Memory::Rpm(uint64_t address, void* buffer, size_t size)
{
	return ReadMemoryFromKernel(processId, address, buffer, size);
}

bool Memory::Wpm(uint64_t address, void* buffer, size_t size)
{
	return WriteMemoryFromKernel(processId, address, buffer, size);
}



BOOL Memory::Setup(LPCSTR routineName) {
	auto win32u = LoadLibraryA("win32u.dll");
	if (!win32u) {
		return FALSE;
	}

	auto addr = GetProcAddress(win32u, routineName);
	if (!addr) {
		return FALSE;
	}

	*(PVOID*)&NtUserCloseWindowStation = addr;
	return TRUE;
}

bool Memory::GetProcessBaseAddressFromKernel(int processID, uint64_t* baseAddress)
{
	Communication request = {};
	SecureZeroMemory(&request, sizeof(Communication));
	request.request = Request::GETBASE;
	request.key = COMMUNICATION_KEY;
	request.processID = processID;
	request.buffer = 0;
	NtUserCloseWindowStation(&request);

	*baseAddress = request.buffer;
	return (request.buffer != NULL);
}

bool Memory::GetModuleBaseAddressFromKernel(int processID, const char* moduleName, uint64_t* baseAddress)
{
	Communication request = {};
	SecureZeroMemory(&request, sizeof(Communication));
	request.request = Request::GETMODULEBASE;
	request.key = COMMUNICATION_KEY;
	request.processID = processID;
	request.moduleName = moduleName;
	request.buffer = 0;
	NtUserCloseWindowStation(&request);

	*baseAddress = request.buffer;
	return (request.buffer != NULL);
}


bool Memory::ReadMemoryFromKernel(int processId, uint64_t address, void* buffer, size_t size)
{
	size_t read = NULL;
	Communication request = {};
	SecureZeroMemory(&request, sizeof(Communication));

	request.request = Request::READPROCESSMEMORY;
	request.key = COMMUNICATION_KEY;
	request.address = address;
	request.buffer = (uint64_t)buffer;
	request.size = size;
	request.processID = processId;
	request.read = read;

	NtUserCloseWindowStation(&request);
	return (buffer != NULL);
}

bool Memory::WriteMemoryFromKernel(int processId, uint64_t address, void* buffer, size_t size)
{
	size_t written = NULL;
	Communication request = {};
	SecureZeroMemory(&request, sizeof(Communication));

	request.request = Request::WRITEPROCESSMEMORY;
	request.key = COMMUNICATION_KEY;
	request.address = address;
	request.buffer = (uint64_t)buffer;
	request.size = size;
	request.processID = processId;
	request.read = written;

	NtUserCloseWindowStation(&request);
	return (buffer != NULL);
}
