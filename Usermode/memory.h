#pragma once
#include <Windows.h>
#include <vector>
#include <map>

class Memory
{
public:
	Memory(int32_t pid, std::vector<std::string> ModuleNames = {});

	template<typename T>
	T Rpm(uint64_t address);
	bool Rpm(uint64_t address, void* buffer, size_t size);

	template<typename T>
	void Wpm(uint64_t address, T value);
	bool Wpm(uint64_t address, void* buffer, size_t size);



	std::map<std::string, uint64_t> moduleBases;

	uint64_t base = 0;
private:
	/*
	* Communication
	*/
#define COMMUNICATION_KEY 0xDEADBEEF
	int32_t processId = 0;

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

	BOOL Setup(LPCSTR routineName);
	bool GetProcessBaseAddressFromKernel(int processID, uint64_t* baseAddress);
	bool GetModuleBaseAddressFromKernel(int processID, const char* moduleName, uint64_t* baseAddress);
	bool ReadMemoryFromKernel(int processId, uint64_t address, void* buffer, size_t size);
	bool WriteMemoryFromKernel(int processId, uint64_t address, void* buffer, size_t size);
}; extern Memory* pMem;

template<typename T>
inline T Memory::Rpm(uint64_t address)
{
	T buffer;
	Rpm(address, &buffer, sizeof(T));
	return buffer;
}

template<typename T>
inline void Memory::Wpm(uint64_t address, T value)
{
	Wpm(address, &value, sizeof(T));
}
