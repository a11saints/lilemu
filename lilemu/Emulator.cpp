#include "Emulator.hpp"

namespace lilemu {
namespace core {

constexpr auto executeInstructionMax = 0x40000;
constexpr auto stackAddress = 0x0;
constexpr auto stackSize = 1024 * 1024;
constexpr auto stackInitValue = 0xFF;

Emulator::Emulator(uint64_t base, uint64_t size, std::vector<uint8_t>& buffer, uc_arch arch, uc_mode mode) :
	arch_{ arch },
	mode_{ mode },
	base_{ base },
	size_{ size },
	buffer_{buffer}
{}


Emulator::~Emulator() {
	uc_close(uc_);
}

void Emulator::init_uc(){
	uc_err err = uc_open(arch_, mode_, &uc_);
	if (err != UC_ERR_OK) {
		throw std::runtime_error("Failed to start");
	}

	/*mem_map(base_, size_, UC_PROT_ALL);
	mem_write(base_, buffer_.data(), size_);*/
	sections_map(buffer_, UC_PROT_ALL);
	init_stack();
	init_reg_table();
	init_ctxt();
	init_data();
}

void Emulator::mem_read(uint64_t address, void* buffer, size_t size) {
	uc_err err = uc_mem_read(uc_, address, buffer, size);
	if (err != UC_ERR_OK) {
		throw std::runtime_error("Failed to read memory");
	}
}

void Emulator::hook_add(uc_hook* hook, int type, void* callback, void* user_data, uint64_t start, uint64_t end) {
	uc_err err = uc_hook_add(uc_, hook, type, callback, user_data, start, end);
	if (err != UC_ERR_OK) {
		error_log(err);
	}
}
void Emulator::mem_map(uint64_t address, uint64_t size, uint32_t permissions) {
	uc_err err = uc_mem_map(uc_, address, size, permissions);
	if (err) {
		error_log(err);
	}
}
template <typename T>
bool Emulator::sections_map(std::vector<T>& buffer, uint32_t permissions) {
	using u64 = uint64_t;
	using u32 = uint32_t;
	using u8 = uint8_t;

	auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

	auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	auto sec = IMAGE_FIRST_SECTION(nt);

	for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		auto& s = sec[i];

		u64 virt_addr = base_ + s.VirtualAddress;
		u64 size_to_map = std::max<u32>(s.SizeOfRawData, s.Misc.VirtualSize);

		size_to_map = (size_to_map + 0xFFF) & ~0xFFF;

		mem_map(virt_addr, size_to_map, UC_PROT_ALL);


		if (s.SizeOfRawData > 0) {
			if ((s.PointerToRawData + s.SizeOfRawData) > buffer.size()) {
				std::cerr << "Section " << i << " raw data out of bounds\n";
				return false;
			}
			 mem_write( virt_addr, buffer.data() + s.PointerToRawData, s.SizeOfRawData);
		}
		spdlog::info("Mapped section {0} at {1:x} size 0x{2:x}", std::string(reinterpret_cast<char*>(s.Name), 8), virt_addr, size_to_map);
		//std::cout << "[+] Mapped section " << std::string(reinterpret_cast<char*>(s.Name), 8) << " at " << std::hex << virt_addr << " size 0x" << size_to_map << "\n";
	}
	return true;
}

void Emulator::mem_write(uint64_t address, void* buffer, size_t size) {
	uc_err err = uc_mem_write(uc_, address, buffer, size);
	if (err) {
		error_log(err);
	}
}

void Emulator::reg_write(const uc_x86_reg&  reg_type, const   uintptr_t* reg_val) {
	uc_err err = uc_reg_write(uc_, reg_type, reg_val);
	if (err) {
		error_log(err);
	}
}
void Emulator::reg_read(const uc_x86_reg&  reg_type, void* reg_val) {
	uc_err err = uc_reg_read(uc_, reg_type,  reg_val);
	if (err) {
		error_log(err);
	}
}

int Emulator::error_log(uc_err err) {
	if (err) {
		printf("\nEmulation error: %s", uc_strerror(err));
		uint64_t fault_addr;
		uc_reg_read(uc_, UC_X86_REG_RIP, &fault_addr);
		printf("\nFault at 0x%" PRIx64 "", fault_addr);
	}
	return 0;
}
void Emulator::emu_start(uint64_t begin, uint64_t until, uint64_t timeout, size_t count) {
	uc_err err = uc_context_restore(uc_, uc_ctxt_);
	if (err!=UC_ERR_OK)
	{
		error_log(err);
	}
	err = uc_mem_write(uc_, stackAddress, stackBuffer, stackSize);
	if (err != UC_ERR_OK)
	{
		error_log(err);
	}

	 err = uc_emu_start(uc_, begin, until, timeout, count);
	if (err) {
		error_log(err);
	}
}

void Emulator::init_stack() {
	stackBuffer = (uint64_t*)malloc(stackSize);
	if (stackBuffer == nullptr) {
		throw std::runtime_error("Failed to malloc");
	}
	else {
		mem_map(stackAddress, stackSize, UC_PROT_ALL);
		memset(stackBuffer, 0xFF, stackSize);
		mem_write(stackAddress, stackBuffer, stackSize);
	}
}

void Emulator::init_reg_table() {
	reg_table_state={
		{UC_X86_REG_RSP, stackAddress + stackSize - sizeof(std::uintptr_t) * 100},
		{UC_X86_REG_RAX, 0x00000001400019F0},
		{UC_X86_REG_RBX, 0x0},
		{UC_X86_REG_RCX, 0x00000011E852000},
		{UC_X86_REG_RDX, 0x00000001400019F0},
		{UC_X86_REG_RBP, 0x0},
		{UC_X86_REG_RSI, 0x0},
		{UC_X86_REG_RDI, 0x0},
		{UC_X86_REG_R8, 0x000000011E852000},
		{UC_X86_REG_R9, 0x0},
		{UC_X86_REG_R10, 0x00007FFAA19FE2F0},
		{UC_X86_REG_R11, 0x0},
		{UC_X86_REG_R12, 0x0},
		{UC_X86_REG_R13, 0x0},
		{UC_X86_REG_R14, 0x0},
		{UC_X86_REG_R15, 0x0}
	};

	for (const auto& [reg, regval] : reg_table_state) {
		reg_write(reg, (uintptr_t*)&regval);
	}
}

void Emulator::init_ctxt() {
	if (uc_context_alloc(uc_, &uc_ctxt_) != UC_ERR_OK) {
		throw("Context allocation fail");
	}
	
	if (uc_context_save(uc_, uc_ctxt_) != UC_ERR_OK) {
		throw("Context save fail");
	}
}

void Emulator::init_data() {
	uint64_t lock_addr = 0x0000001400055F8-0xC00; // fill actual offset
	uint64_t mz_header = 0x000000013FFFF400-0xC00; // fill actual offset
	uint64_t one = 0;
	uint16_t MZ = 0x5A4D;
	uc_mem_write(uc_, lock_addr, &one, sizeof(one));
	uc_mem_write(uc_, mz_header, &MZ, sizeof(MZ));

}

uc_x86_reg Emulator::reg_table[] = {
	UC_X86_REG_RAX,
	UC_X86_REG_RCX,
	UC_X86_REG_RDX,
	UC_X86_REG_RBX,
	UC_X86_REG_RSP,
	UC_X86_REG_RBP,
	UC_X86_REG_RSI,
	UC_X86_REG_RDI,
	UC_X86_REG_R8,
	UC_X86_REG_R9,
	UC_X86_REG_R10,
	UC_X86_REG_R11,
	UC_X86_REG_R12,
	UC_X86_REG_R13,
	UC_X86_REG_R14,
	UC_X86_REG_R15
};

} // namespace core
} // namespace lilemu