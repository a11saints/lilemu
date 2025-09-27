#pragma once
#include <Zydis/Zydis.h>
#include "IncludeMe.hpp"

namespace lilemu {
namespace core {

/**
 * @param   runtime_address_		Address of data to be mapped.
 * @param	data_					Buffer of bytes to be disassembled.
 * @param   offset_					Entrypoint.
*/
class Disassembler {
public:
	Disassembler(ZyanU64 runtime_address_, std::vector<ZyanU8>& data_, ZyanUSize& offset_);
	~Disassembler();
	void zDecoder();
	void Disass(uint64_t addr, std::vector<ZyanU8> &bytes, ZyanUSize off, ZydisDisassembledInstruction& di);
	void zDisassembler();
	int Init();

private:

	// The runtime address (instruction pointer) was chosen arbitrarily here in order to better
	// visualize relative addressing. In your actual program, set this to e.g. the memory address
	// that the code being disassembled was read from.

	//ZyanU64 runtime_address = 0x007FFFFFFF400000;
	//ZyanUSize offset = nt->OptionalHeader.AddressOfEntryPoint;
	ZydisDisassembledInstruction disass_instruction;
	ZydisDecodedInstruction decoded_instruction;

	ZydisFormatter formatter;
	ZydisDecoder decoder;

	std::vector< ZydisDecodedOperand> operands{ ZYDIS_MAX_OPERAND_COUNT };
	std::vector<ZyanU8> data;

	ZyanU64 runtime_address = 0;
	ZyanUSize offset = 0;

	const ZyanUSize length = 0;;
};

} // namespace core
} // namespace lilemu
