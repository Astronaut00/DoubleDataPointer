// Example.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "..\Usermode\memory.h"

Memory* pMem = nullptr;
int main()
{
    LoadLibraryA("user32.dll");

    uint32_t processId = GetCurrentProcessId();
    pMem = new Memory(processId, { "user32.dll" });

    std::cout << "Process Base: " << pMem->base  << std::endl;
    std::cout << "user32.dll Base: " << pMem->moduleBases["user32.dll"] << std::endl;

    int x = 100;
    std::cout << "Rpm: " << pMem->Rpm<int>((uint64_t)&x) << std::endl;

    pMem->Wpm<int>((uint64_t)&x, 15);
    std::cout << "After Wpm: " << x << std::endl;

    return 0;
}