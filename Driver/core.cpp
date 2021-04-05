#pragma once
#include "core.h"
#include "structs.h"

namespace Core {

    NTSTATUS GetProcessBaseAddress(int pid, uint64_t* Address)
    {
        PEPROCESS pProcess = NULL;
        if (pid < 1) 
            return STATUS_UNSUCCESSFUL;

        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pProcess)))
            return STATUS_UNSUCCESSFUL;


        *Address = (uint64_t)PsGetProcessSectionBaseAddress(pProcess);

        ObDereferenceObject(pProcess);
        return STATUS_SUCCESS;
    }

    DWORD GetUserDirectoryTableBaseOffset()
    {
        RTL_OSVERSIONINFOW ver = { 0 };
        RtlGetVersion(&ver);

        switch (ver.dwBuildNumber)
        {
        case WINDOWS_1803:
            return 0x0278;
            break;
        case WINDOWS_1809:
            return 0x0278;
            break;
        case WINDOWS_1903:
            return 0x0280;
            break;
        case WINDOWS_1909:
            return 0x0280;
            break;
        case WINDOWS_2004:
            return 0x0388;
            break;
        case WINDOWS_20H2:
            return 0x0388;
            break;
        case WINDOWS_21H1:
            return 0x0388;
            break;
        default:
            return 0x0388;
        }
    }

    //check normal dirbase if 0 then get from UserDirectoryTableBas
    ULONG_PTR GetProcessCr3(PEPROCESS pProcess)
    {
        PUCHAR process = (PUCHAR)pProcess;
        ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
        if (process_dirbase == 0)
        {
            DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
            ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
            return process_userdirbase;
        }
        return process_dirbase;
    }
    ULONG_PTR GetKernelDirBase()
    {
        PUCHAR process = (PUCHAR)PsGetCurrentProcess();
        ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
        return cr3;
    }
    uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress);
    NTSTATUS ReadPhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
    NTSTATUS WritePhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);

    NTSTATUS ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read)
    {
        uint64_t paddress = TranslateLinearAddress(dirbase, address);
        return ReadPhysicalAddress(paddress, buffer, size, read);
    }

    NTSTATUS WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written)
    {
        uint64_t paddress = TranslateLinearAddress(dirbase, address);
        return WritePhysicalAddress(paddress, buffer, size, written);
    }

    NTSTATUS ReadPhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
    {
        MM_COPY_ADDRESS AddrToRead = { 0 };
        AddrToRead.PhysicalAddress.QuadPart = TargetAddress;
        return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
    }

    //MmMapIoSpaceEx limit is page 4096 byte
    NTSTATUS WritePhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
    {
        if (!TargetAddress)
            return STATUS_UNSUCCESSFUL;

        PHYSICAL_ADDRESS AddrToWrite = { 0 };
        AddrToWrite.QuadPart = TargetAddress;

        PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

        if (!pmapped_mem)
            return STATUS_UNSUCCESSFUL;

        memcpy(pmapped_mem, lpBuffer, Size);

        *BytesWritten = Size;
        MmUnmapIoSpace(pmapped_mem, Size);
        return STATUS_SUCCESS;
    }

#define PAGE_OFFSET_SIZE 12
    static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

    uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress) {
        directoryTableBase &= ~0xf;

        uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
        uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
        uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
        uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
        uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

        SIZE_T readsize = 0;
        uint64_t pdpe = 0;
        ReadPhysicalAddress(directoryTableBase + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
        if (~pdpe & 1)
            return 0;

        uint64_t pde = 0;
        ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde), &readsize);
        if (~pde & 1)
            return 0;

        /* 1GB large page, use pde's 12-34 bits */
        if (pde & 0x80)
            return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

        uint64_t pteAddr = 0;
        ReadPhysicalAddress((pde & PMASK) + 8 * pt, &pteAddr, sizeof(pteAddr), &readsize);
        if (~pteAddr & 1)
            return 0;

        /* 2MB large page */
        if (pteAddr & 0x80)
            return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

        virtualAddress = 0;
        ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof(virtualAddress), &readsize);
        virtualAddress &= PMASK;

        if (!virtualAddress)
            return 0;

        return virtualAddress + pageOffset;
    }


    //
    NTSTATUS ReadProcessMemory(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* read)
    {
        PEPROCESS pProcess = NULL;
        if (pid == 0) return STATUS_UNSUCCESSFUL;

        NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
        if (NtRet != STATUS_SUCCESS) return NtRet;

        ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
        ObDereferenceObject(pProcess);

        SIZE_T CurOffset = 0;
        SIZE_T TotalSize = size;
        while (TotalSize)
        {

            uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
            if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

            ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
            SIZE_T BytesRead = 0;
            NtRet = ReadPhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
            TotalSize -= BytesRead;
            CurOffset += BytesRead;
            if (NtRet != STATUS_SUCCESS) break;
            if (BytesRead == 0) break;
        }

        *read = CurOffset;
        return NtRet;
    }

    NTSTATUS WriteProcessMemory(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* written)
    {
        PEPROCESS pProcess = NULL;
        if (pid == 0) return STATUS_UNSUCCESSFUL;

        NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
        if (NtRet != STATUS_SUCCESS) return NtRet;

        ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
        ObDereferenceObject(pProcess);

        SIZE_T CurOffset = 0;
        SIZE_T TotalSize = size;
        while (TotalSize)
        {
            uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
            if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

            ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
            SIZE_T BytesWritten = 0;
            NtRet = WritePhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
            TotalSize -= BytesWritten;
            CurOffset += BytesWritten;
            if (NtRet != STATUS_SUCCESS) break;
            if (BytesWritten == 0) break;
        }

        *written = CurOffset;
        return NtRet;
    }

    //NTSTATUS GetModuleBaseAddress(int processId, const char* moduleName, uint64_t* baseAddress)
    //{
    //    printf("Trying to Find: %s\n", moduleName);
    //    if (!moduleName)
    //        return STATUS_UNSUCCESSFUL;


    //    /*PEPROCESS process = NULL;
    //    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)processId, &process)))
    //        return STATUS_UNSUCCESSFUL;

    //    printf("Found PEPROCESS\n\n", moduleName);

    //    PPEB pPeb = PsGetProcessPeb(process);

    //    if (!pPeb)
    //        return STATUS_UNSUCCESSFUL;

    //    printf("Found PEB\n\n", moduleName);*/

    //    ANSI_STRING ansiString = { 0 };
    //    RtlInitAnsiString(&ansiString, moduleName);

    //    if (ansiString.Length < 3)
    //        return STATUS_UNSUCCESSFUL;

    //    UNICODE_STRING compareString = { 0 };
    //    RtlAnsiStringToUnicodeString(&compareString, &ansiString, TRUE);

    //    if (compareString.Length < 3)
    //        return STATUS_UNSUCCESSFUL;

    //    PEPROCESS pProcess = NULL;
    //    NTSTATUS status = STATUS_UNSUCCESSFUL;
    //    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)processId, &pProcess)))
    //    {
    //        KAPC_STATE state;
    //        KeStackAttachProcess(pProcess, &state);
    //        PPEB pPeb = PsGetProcessPeb(pProcess);

    //        for (PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink; pListEntry != &pPeb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
    //        {
    //            PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    //            if (RtlCompareUnicodeString(&pEntry->BaseDllName, &compareString, TRUE) == 0) {
    //                *baseAddress = (uint64_t)pEntry->DllBase;
    //                status = STATUS_SUCCESS;
    //                break;
    //            }
    //        }

    //        KeUnstackDetachProcess(&state);
    //    }
    //    return status;
    //}

    NTSTATUS GetModuleBaseAddress(int processId, const char* moduleName, uint64_t* baseAddress)
    {
        ANSI_STRING ansiString;
        UNICODE_STRING compareString;
        KAPC_STATE state;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        PEPROCESS process = NULL;
        PPEB pPeb = NULL;

        RtlInitAnsiString(&ansiString, moduleName);
        RtlAnsiStringToUnicodeString(&compareString, &ansiString, TRUE);

        printf("Looking for module %d\n", processId);

        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)processId, &process)))
            return STATUS_UNSUCCESSFUL;

        printf("Found process %d\n", processId);

        KeStackAttachProcess(process, &state);
        pPeb = PsGetProcessPeb(process);

        if (pPeb)
        {
            PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

            if (pLdr)
            {
                for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InMemoryOrderModuleList.Flink; list != &pLdr->InMemoryOrderModuleList; list = (PLIST_ENTRY)list->Flink)
                {
                    PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    printf("%wZ\n", pEntry->BaseDllName);
                    if (RtlCompareUnicodeString(&pEntry->BaseDllName, &compareString, TRUE) == 0)
                    {
                        *baseAddress = (uint64_t)pEntry->DllBase;
                        status = STATUS_SUCCESS;
                        break;
                    }
                }
            }
        }
        KeUnstackDetachProcess(&state);
        RtlFreeUnicodeString(&compareString);
        return status;
    }

    PVOID GetSystemModuleBase(LPCSTR moduleName) {

        PVOID moduleBase = NULL;
        ULONG info = 0;

        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);

        if (!info) {
            return moduleBase;
        }

        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, info, 0x89109929301);

        status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);

        if (!NT_SUCCESS(status)) {
            return moduleBase;
        }

        PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;


        if (modules->NumberOfModules > 0) {

            if (!moduleName) {
                moduleBase = modules->Modules[0].ImageBase;
            }
            else {

                for (auto i = 0; i < modules->NumberOfModules; i++) {
                    printf("module[i].FullPathName: %s", module[i].FullPathName);
                    if (!strcmp((CHAR*)module[i].FullPathName, moduleName)) {
                        moduleBase = module[i].ImageBase;
                    }
                }
            }
        }

        if (modules) {
            ExFreePoolWithTag(modules, 0x89109929301);
        }

        return moduleBase;
    }

}