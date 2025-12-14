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

std::wstring target { L"..\\..\\lilemu\\lilemu\\Target\\reveng_20%vm_antidebug.exe" };

using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8 = uint8_t;

 constexpr u64 BASE_ADDR = 0x0000000140000000;
constexpr u64 RVA_TEXT = 0x1000;
constexpr u64 RAW_TEXT = 0x400;
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

IMAGE_SECTION_HEADER* textSection = new IMAGE_SECTION_HEADER{ sizeof(IMAGE_SECTION_HEADER) };
void* textSectionPtr = new std::byte{ sizeof(IMAGE_SECTION_HEADER) * 2 };


static void mainCallback() {}

bool checkModuleBoundaries(uint64_t address) {
	IMAGE_SECTION_HEADER* textSection= reinterpret_cast<IMAGE_SECTION_HEADER*>(textSectionPtr);
	uint64_t textEnd= BASE_ADDR + textSection->VirtualAddress + textSection->SizeOfRawData;
	uint64_t textStart = BASE_ADDR + textSection->VirtualAddress;
	return (address < textStart) && (address > textEnd);
}


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
	uint8_t code[16]{0};

	uc_err error = uc_mem_read(uc, address, code, size);
	if (error != UC_ERR_OK) {
		spdlog::error("Error: ", uc_strerror(error));
	}
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
		bool c = checkModuleBoundaries(b);
		if (c) spdlog::warn("Call outside of .text section");
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

template <typename T>
int findOffset(T ptr, std::vector<ZyanU8> pattern) {
	auto it = std::search(ptr.begin(), ptr.end(), pattern.begin(), pattern.end());
	
	if (it != ptr.end()) {
		return std::distance(ptr.begin(), it);
	}
	else {
		return 0;
	}
	return 0;
}


int main() {
	spdlog::info("Started.");
	Process process{};
	std::cout << GetLastError();
	int pid;
	std::cout << "enter pid: ";
	//std::cin >> pid;
	int s = process.Attach(24536);
	std::cout << GetLastError();

	if (GetLastError()==0) {
		auto& memory = process.memory();
		auto& modules = process.modules();
		auto& procesCore = process.core();
		auto mainModule = modules.GetMainModule();
		void* moduleBuffer = new std::byte[mainModule->size]{};

		IMAGE_SECTION_HEADER *text = new IMAGE_SECTION_HEADER{sizeof(IMAGE_SECTION_HEADER)};

		if (!memory.Read(mainModule->baseAddress, mainModule->size, moduleBuffer)) {
			blackbone::pe::PEImage peImage;
			peImage.Parse(moduleBuffer);
			std::vector<IMAGE_SECTION_HEADER> vecImageSectionHeaders;
			for (auto& section : peImage.sections()) {
				vecImageSectionHeaders.emplace_back(section);
				if (strcmp((char*)section.Name, ".text")==0) {
					textSectionPtr = (void*) &section;
				}

			}
			uint64_t mainModuleImageBase = peImage.imageBase();
			uint64_t mainModuleEntryPoint = peImage.entryPoint(mainModuleImageBase);
			spdlog::info("\nEntry point in emulator: {0:x}", mainModuleEntryPoint);
			
	


			std::vector<ZyanU8> zcode;
			zcode.resize(mainModule->size);
			// std::memcpy(zcode.data(), moduleBuffer, zcode.size());

			
			auto FileOffsetToVA = [&](size_t fileOffset) -> uint64_t {
				for (const auto& sec : peImage.sections()) {
					if (fileOffset >= sec.PointerToRawData && fileOffset < sec.PointerToRawData + sec.SizeOfRawData) {
						uint32_t rva = static_cast<uint32_t>(fileOffset - sec.PointerToRawData + sec.VirtualAddress);
						return BASE_ADDR + rva; // or mainModule->baseAddress + rva if using actual loaded base
					}
				}
				return BASE_ADDR; // fallback
				};

			
			//auto imgSize = peImage.imageSize(); // or peImage.headers().optionalHeader.SizeOfImage
			//for (const auto& sec : peImage.sections()) {
			//	if (sec.SizeOfRawData == 0) continue;
			//	uint64_t destRva = sec.VirtualAddress;
			//	uint64_t srcOffset = sec.PointerToRawData;
			//	// bounds check:
			//	if (srcOffset + sec.SizeOfRawData <= mainModule->size && destRva + sec.SizeOfRawData <= zcode.size()) {
			//		std::memcpy(zcode.data() + destRva, static_cast<std::byte*>(moduleBuffer) + srcOffset, sec.SizeOfRawData);

			//	}
			//}

			uint8_t buffer[10]={0};
			memory.Read(0x0000000140000000, buffer);
			for (auto i : buffer) {
				std::cout << i << " ";
			}
			memory.Read(mainModule->baseAddress,  zcode.size(), zcode.data());
			uint64_t entry = findOffset<std::vector<ZyanU8>>(zcode, std::vector<ZyanU8>{ 0x41, 0x52, 0x49, 0xba });
			spdlog::info("Found pattern at offset: {0:x}", entry);
			entry += BASE_ADDR;

			
			
			
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
			// -0x750a00


			emulator->StartEmulator(BASE_ADDR+0x8c786f, BASE_ADDR + zcode.size() /*- (mainModuleEntryPoint - BASE_ADDR)*/, 0, 0);
			Sleep(50000);
		}
	}

	return 0;
}
