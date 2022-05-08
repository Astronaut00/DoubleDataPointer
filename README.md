# DoubleDataPointer
Double data pointer communication in to the kernel mode, the driver should be manually mapped into the kernel.

This project points a data pointer at another data pointer which is pointed to memory inside of the driver. This allows a user to send commands through a uncommonly used windows API, and execute commands at a kernel permission level.

Features:
- Read Memory
- Write Memory
- Nulls Page Frame numbers of the driver (so it is harder to find the pages with the driver stub)
- Clears Big pools (Usually ExAllocatePool is used to allocate the driver when manually mapping, this takes the driver out of the pig pool tables)
- Physical Memory Read/Write (KeStackAttach can be detected, which is used inside of MmCopyVirtualMemory)

Useful for bypassing Anti-Cheat solutions.
