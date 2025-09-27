#include "Format"
#include "Emulator.hpp"
#include "Disassembler.hpp"
#include <string>
#include "ApiResolver.hpp"

Disassembler* disassembler;
Emulator* emulator;
std::map<std::string, std::pair<uint64_t, uint64_t>>* sections_map;
ZydisDisassembledInstruction* disassembledInstruction = new ZydisDisassembledInstruction;
HMODULE pe;

using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8 = uint8_t;

inline constexpr u64 BASE_ADDR = 0x0000000140000000;
inline constexpr u64 RVA_TEXT = 0x1000;
inline constexpr u64 RAW_TEXT = 0x400;
inline constexpr u64 RVA_DELTA = RVA_TEXT - RAW_TEXT;

int sections(HMODULE &pe, std::map<std::string, std::pair<uint64_t,uint64_t>>* sections_map) {
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(pe);
	auto opt_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(pe);
	int imageSize = opt_header->SizeOfImage;
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((uint8_t*)pe + dos_header->e_lfanew);
	auto sec = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		auto& s = sec[i];
		sections_map->insert( { std::string(reinterpret_cast<char*>(s.Name), 8), {s.VirtualAddress,s.VirtualAddress + s.SizeOfRawData} } );
	}
	return 0;
}

std::pair<int,int> img() {
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(pe);
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((uint8_t*)pe + dos_header->e_lfanew);
	int imageSize = nt->OptionalHeader.SizeOfImage;
	int imageBase = nt->OptionalHeader.ImageBase;
	return { imageBase, imageSize };
}

bool readFile(std::vector<ZyanU8>& dst, const std::string& filepath) {
	std::ifstream file(filepath, std::ios::binary | std::ios::ate);
	if (!file) {
		std::perror("ifstream failed");
		return false;
	}
	std::streamsize size = file.tellg();
	if (size < 0) {
		std::perror("tellg failed");
		return false;
	}

	file.seekg(0, std::ios::beg);
	dst.resize(static_cast<std::size_t>(size) + 0x1000); // reserve + extra 0x1000
	//@note: @a11saints: char, unsigned char, and std::byte all guarantee no strict aliasing violation.
	if (!file.read(reinterpret_cast<char*>(dst.data()), size)) {
		std::cerr << "ifstream read failed\n";
		return false;
	}
	return true;
}

//void ParseIAT(const std::wstring& path, const std::wstring& processName) {
//	using namespace blackbone;
//	Process process;
//	int pid;
//	process.CreateAndAttach(path);
//
//	if (0) {
//		auto pids = Process::EnumByName(processName.c_str());
//		if (!process.Attach(pid)) {
//			std::wcerr << L"Failed to attach to process: " << processName << std::endl;
//			return;
//		}
//	}
//
//	auto& sMemory = process.memory();
//	auto& sModules = process.modules();
//	auto& sCore = process.core();
//	const ModuleDataPtr &module = sModules.GetMainModule();
//}

bool checkModuleBoundaries(uint64_t address) {
	auto pe = img();
	u64 nigger = BASE_ADDR + pe.second;
	return address < BASE_ADDR &&  address > nigger;
}

bool  is_call(uint8_t byte[16] ) {
	if (byte[0] == 0xFF && byte[1] ==0x15) return true;
	return false;
}

static void main_callback() {}

/*
static void c_emulator::Kernel32_ExitProcess() {
	uint32_t exit_code = reinterpret_cast<uint32_t>(emulator->get_arg(0));
	printf("ExitProcess(uExitCode: %p) call\n", exit_code);
	uc_emu_stop(emulator->m_uc);
	emulator->ret(0, 1);
}
*/

static void handle_call() {
	// E8 call
	// FF call
	// 9A call

}

uint64_t extract_call_address() {
	return 0;
}

static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	//std::cout << "\n " << std::hex << address<<" | ";
	uint8_t code[16];
	uc_mem_read(uc, address, code, size);
	std::vector<ZyanU8> bytes(std::begin(code), std::end(code));
	std::string nigger;

	u64 addr = *reinterpret_cast<u64*>(code);
	
	disassembler->Disass(address, bytes, 0, *disassembledInstruction);
	if (is_call(code)) {
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

void hook_mem(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user_data) {
	printf("Memory access at 0x%" PRIx64 "\n", addr);
}

int main() {
	spdlog::info("Welcome to spdlog!");
	spdlog::error("Some error message with arg: {}", 1);
	spdlog::warn("Easy padding in numbers like {:08d}", 12);
	spdlog::critical("Support for int: {0:d};  hex: {0:x};  oct: {0:o}; bin: {0:b}", 42);
	spdlog::info("Support for floats {:03.2f}", 1.23456);
	spdlog::info("Positional args are {1} {0}..", "too", "supported");
	spdlog::info("{:<30}", "left aligned");
	spdlog::set_level(spdlog::level::debug); // Set *global* log level to debug
	spdlog::debug("This message should be displayed..");

	// change log pattern
	//spdlog::set_pattern("[%H:%M:%S %z] [%n] [%^---%L---%$] [thread %t] %v");

	// Compile time log levels
	// Note that this does not change the current log level, it will only
	// remove (depending on SPDLOG_ACTIVE_LEVEL) the call on the release code.
	SPDLOG_TRACE("Some trace message with param {}", 42);
	SPDLOG_DEBUG("Some debug message");

	const char* filename = "C:\\Users\\allsaints\\Documents\\Controlled Folder\\Devirtualization\\reveng\\x64\\Release\\reveng_Od_vmp_cond_20perc_vm.exe";
	
	//ParseIAT(filename);


	sections_map = new std::map<std::string, std::pair<uint64_t,uint64_t>>();

	uint64_t BASE_ADDR = 0x0000000140000000;
	size_t CODE_SIZE = 0x00241000;

	std::vector<ZyanU8> zcode;
	zcode.reserve(CODE_SIZE);
	readFile(zcode, filename);
	pe = LoadLibraryA(filename);
	//sections(pe, sections_map);
	
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(pe);
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((uint8_t*)pe + dos_header->e_lfanew);
	int imageSize  = nt->OptionalHeader.SizeOfImage;
	int imageBase = nt->OptionalHeader.ImageBase;

	auto sec = IMAGE_FIRST_SECTION(nt);

	auto RvaToRaw = [&](DWORD rva) -> DWORD {
		for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
			if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
				return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
		return 0;
	};

	ZyanUSize raw_entry = 0;
	auto entry_point = static_cast<uint64_t>(BASE_ADDR + nt->OptionalHeader.AddressOfEntryPoint);
	
	spdlog::info("\nEntry point in emulator: {0:x}", entry_point);

	//@note: It raises confusion the fact, that we pass, entrypoint and offset to entrypoint,
	// but entrypoint address is merely used to print currently disassembled instructions
	// internally only buffer and offset udsed to locate data to be disassembled

	disassembler = new Disassembler(entry_point, zcode, raw_entry);

	//uint64_t entry_point = runtime_address + nt->OptionalHeader.AddressOfEntryPoint;
	emulator = new Emulator(BASE_ADDR , CODE_SIZE, zcode, UC_ARCH_X86, UC_MODE_64);
	emulator->init_uc();
	
	uc_hook mem_hook;
	emulator->hook_add(&mem_hook, UC_HOOK_CODE, hook_code, NULL, BASE_ADDR, BASE_ADDR+CODE_SIZE);
	//emulator->hook_add(&mem_hook, UC_HOOK_INSN, hook_mem, NULL, 0, 1);
	
	emulator->emu_start(0x0000001400010A0, BASE_ADDR + CODE_SIZE - (entry_point - BASE_ADDR), 0, 0);
	Sleep(50000);
	return 0;
}


/*
	std::vector<ZyanU8> d{ 0x48, 0x89 , 0x05 , 0xDA , 0x31 , 0x00 , 0x00 };
	std::vector<ZyanU8> a{ 0x48, 0x83, 0xEC, 0x28 };
	std::vector<ZyanU8> c{ 0xE8, 0xC7, 0x03, 0x00, 0x00 };
	std::vector<ZyanU8> b{ 0x48, 0x89, 0x5C, 0x24, 0x18 };
	ds->Disass(1, d, 0); // mov [0x00000000000031E2], rax 
	ds->Disass(1, a, 0); //sub rsp, 0x28 
	ds->Disass(1, c, 0); // call 0x00000000000003CD
	ds->Disass(1, b, 0); // mov [rsp+0x18], rbx
	ds->zDisassembler();
	ds->zDecoder();

	// @note: @a11saints: used to be proc to add some context during execution (i.e. setting value at specific address).
static void isInsn(uint64_t address, uint8_t opcode[]) {
	uint64_t addr = 0x0000001400055F8;
	uint8_t val[] = { 0x62, 0xA0, 0x50, 0x00,0x00 };
	uint8_t buff[16] = { };
	
	emulator->mem_write(addr, &val, sizeof(val));
	emulator->mem_read(addr, buff, 16);
	std::cout << "\n mem_read: ";
	for (int i = 0; i < 16; ++i) {
		printf("%02X ", buff[i]);
	}
}
	
*/


/*
uint64_t* memRead(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user_data) {
	uint8_t code[16];
	uc_mem_read(uc, addr, code, size);
	const auto& op = code[i];
	if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint64_t target = 0;
		if (op.mem.base == ZYDIS_REGISTER_RIP) {
			target = addr + instruction.length + op.mem.disp.value;
		}
		else if (op.mem.base == ZYDIS_REGISTER_NONE) {
			target = op.mem.disp.value;
		}
		else {
			// for full EA: base + index * scale + displacement
			// you'd need to read register values
			target = op.mem.disp.value; // fallback
		}
		printf("Resolved memory operand: 0x%llx\n", target);
	}
	emulator->reg_read()
}
*/