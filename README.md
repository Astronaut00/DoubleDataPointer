# DoubleDataPointer
Double data pointer communication in to the kernel mode, the driver should be manually mapped into the kernel. Useful for bypassing Anti-Cheat solutions.

This project points a data pointer at another data pointer which is pointed to memory inside of the driver. This allows a user to send commands through a uncommonly used windows API, and execute commands at a kernel permission level.

Features:
- Read Memory
- Write Memory
- Nulls Page Frame numbers of the driver (so it is harder to find the pages with the driver stub)
- Clears Big pools (Usually ExAllocatePool is used to allocate the driver when manually mapping, this takes the driver out of the pig pool tables)
- Physical Memory Read/Write (KeStackAttach can be detected, which is used inside of MmCopyVirtualMemory)
- Uses 2 data pointers so that a surface level check on the first pointer is not outside of a valid module

Limitations/Detections:
- RIP will be outisde of a valid memory region whenever a stack frame is captured from NMI callbacks. This way anticheats can flag you.
- This project creates alertable threads that can be indexed and captured, later anylyzed or checked for abnormalities.
- The data pointer itself can be directly verified to point to a specific region.

This project was created ages ago, it is most definetly detected.
