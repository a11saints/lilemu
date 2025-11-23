#include "Format"
#include "Emulator.hpp"
#include "Disassembler.hpp"
#include <string>
#include "ApiResolver.hpp"

#include <BlackBone/Process/ProcessCore.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/PE/PEImage.h>

Disassembler* disassembler;
Emulator* emulator;
ZydisDisassembledInstruction* disassembledInstruction = new ZydisDisassembledInstruction;

std::wstring target { L"..\\..\\lilemu\\target\\reveng_Od_vmp_cond_20perc_vm.exe" };

using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8 = uint8_t;

inline constexpr u64 BASE_ADDR = 0x0000000140000000;
inline constexpr u64 RVA_TEXT = 0x1000;
inline constexpr u64 RAW_TEXT = 0x400;
inline constexpr u64 RVA_DELTA = RVA_TEXT - RAW_TEXT;

/*
void ParseIAT(const std::wstring& path, const std::wstring& processName) {
	using namespace blackbone;
	Process process;
	int pid;
	process.CreateAndAttach(path);

	if (0) {
		auto pids = Process::EnumByName(processName.c_str());
		if (!process.Attach(pid)) {
			std::wcerr << L"Failed to attach to process: " << processName << std::endl;
			return;
		}
	}

	auto& sMemory = process.memory();
	auto& sModules = process.modules();
	auto& sCore = process.core();
	const ModuleDataPtr &module = sModules.GetMainModule();
}


static void c_emulator::Kernel32_ExitProcess() {
	uint32_t exit_code = reinterpret_cast<uint32_t>(emulator->GetArg(0));
	printf("ExitProcess(uExitCode: %p) call\n", exit_code);
	uc_emu_stop(emulator->m_uc);
	emulator->ret(0, 1);
}
*/

bool  isCall(uint8_t byte[16] ) {
	if (byte[0] == 0xFF && byte[1] ==0x15) return true;
	return false;
}

static void mainCallback() {}

static void handleCall() {
	// E8 call
	// FF call
	// 9A call

}

uint64_t extractCallAddress() {
	return 0;
}

static void hookCode(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	//std::cout << "\n " << std::hex << address<<" | ";
	uint8_t code[16];
	uc_mem_read(uc, address, code, size);
	std::vector<ZyanU8> bytes(std::begin(code), std::end(code));
	std::string nigger;

	u64 addr = *reinterpret_cast<u64*>(code);
	
	disassembler->Disass(address, bytes, 0, *disassembledInstruction);
	if (isCall(code)) {
		u8 opcode[8];
		uc_mem_read(uc, addr, opcode, size);
		uint64_t next_rip = address + 6;
		int32_t disp = *(int32_t*)&opcode[2];
		uint64_t iat_address = next_rip + disp;

		std::string a(disassembledInstruction->text);
		a = a.substr(6, 18);
		uint64_t b = 0;
		b = std::stoull(a, nullptr, 16);
	/*	bool c = checkModuleBoundaries(b);
		if (c) spdlog::warn("Call outside of .text section");*/
	}
	for (int i = 0; i < size; ++i) {
		if (i != 0) nigger += " ";
		nigger += std::format("{:02x}", code[i]);
	}

	spdlog::info("{0:x} | {1} | {2}", address, nigger, disassembledInstruction->text);

	//Sleep(50);
}

void hookMemory(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user_data) {
	printf("Memory access at 0x%" PRIx64 "\n", addr);
}


using namespace blackbone;
using namespace blackbone::pe;


int main() {
	spdlog::info("Started.");
	Process process{};
	std::cout << GetLastError();
	if (!process.CreateAndAttach(target, true)) {
		auto& memory = process.memory();
		auto& modules = process.modules();
		auto& procesCore = process.core();
		auto mainModule = modules.GetMainModule();
		void* moduleBuffer = new std::byte[mainModule->size]{};

		if (!memory.Read(mainModule->baseAddress, mainModule->size, moduleBuffer)) {
			blackbone::pe::PEImage peImage;
			peImage.Parse(moduleBuffer);
			std::vector<IMAGE_SECTION_HEADER> vecImageSectionHeaders;
			for (auto& section : peImage.sections()) {
				vecImageSectionHeaders.emplace_back(section);
			}
			uint64_t mainModuleImageBase = peImage.imageBase();
			uint64_t mainModuleEntryPoint = peImage.entryPoint(mainModuleImageBase);
			spdlog::info("\nEntry point in emulator: {0:x}", mainModuleEntryPoint);

			std::vector<ZyanU8> zcode;
			zcode.resize(mainModule->size);

			memcpy(zcode.data(), moduleBuffer, zcode.size());
			
			/*
			@note: It raises confusion the fact, that we pass, entrypoint and offset to entrypoint,
			but entrypoint address is merely used to print currently disassembled instructions
			internally only buffer and offset udsed to locate data to be disassembled
			*/

			ZyanUSize rawEntry = 0;
			disassembler = new Disassembler(mainModuleEntryPoint, zcode, rawEntry);

			emulator = new Emulator(BASE_ADDR, zcode.size(), zcode, UC_ARCH_X86, UC_MODE_64);
			emulator->InitUC();

			uc_hook memoryHook;
			emulator->AddHook(&memoryHook, UC_HOOK_CODE, hookCode, NULL, BASE_ADDR, BASE_ADDR + zcode.size());
			//emulator->AddHook(&mem_hook, UC_HOOK_INSN, hookMemory, NULL, 0, 1);

			emulator->StartEmulator(0x0000001400010A0, BASE_ADDR + zcode.size() - (mainModuleEntryPoint - BASE_ADDR), 0, 0);
			Sleep(50000);
		}
	}

	return 0;
}
