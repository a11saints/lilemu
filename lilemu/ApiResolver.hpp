#pragma once

#include <windows.h>
#include <map>
#include <unordered_map>
#include "Emulator.hpp"

extern Emulator* emulator;

namespace callbacks {
	namespace kernel32 {
		int ExitProcess();
	}

	namespace crt {
		uint64_t ios_base__width();
	}
};

namespace utils {
	bool openProcessHandle(DWORD dwPID);
}