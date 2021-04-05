#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>

#include "structs.h"

#define RVA(addr, size)			((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))
#define printf(text, ...)		(DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, text, ##__VA_ARGS__))
//#define WINVER_2004				(19041)
#define COMMUNICATION_KEY		(0xDEADBEEF)


typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

enum Request {
	GETBASE = 0,
	GETMODULEBASE = 1,
	READPROCESSMEMORY = 2,
	WRITEPROCESSMEMORY = 3,
	SIGSCAN = 4
};



struct Communication {

	uint64_t key;
	Request request;

	int processID;

	uint64_t address;
	const char* moduleName;

	uint64_t buffer;
	size_t size;

	union
	{
		size_t written;
		size_t read;
	};
};

struct EntryParams
{
	uint64_t poolBase;
	uint32_t entryPoint;
	uint32_t size;
};

extern "C" NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
extern "C" NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

#include "memory.h"
#include "util.h"
#include "core.h"