#include "Disassembler.hpp"

namespace lilemu {
namespace core {

/**
* @param   runtime_address_		Address of data to be mapped.
* @param	data_					Buffer of bytes to be disassembled.
* @param   offset_					Entrypoint.
*/
Disassembler::Disassembler(ZyanU64 runtime_address_, std::vector<ZyanU8>& data_, ZyanUSize& offset_) :
	runtime_address{ runtime_address_ },
	data{ data_ },
	offset{ offset_ },
	length{ data_.size() }
{ Init(); }

Disassembler::~Disassembler(){};

int Disassembler::Init() {

	if (ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64) != ZYAN_STATUS_SUCCESS) {
		fprintf(stderr, "Decoder init failed\n");
		return 1;
	}

	// Initialize Intel-style formatter
	if (ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL) != ZYAN_STATUS_SUCCESS) {
		fprintf(stderr, "Formatter init failed\n");
		return 1;
	}
}

void Disassembler::Disass(uint64_t addr, std::vector<ZyanU8>& bytes, ZyanUSize off, ZydisDisassembledInstruction& dis) {
	ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		addr,
		bytes.data() + off,
		sizeof(bytes.data()) - off,
		&disass_instruction
	);
	//printf("\n %016" PRIX64 " %s ", runtime_address, disass_instruction.text);
	//printf(" | %s ", disass_instruction.text);
	dis = disass_instruction;
}

void Disassembler::zDecoder() {

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
		&decoder,
		data.data() + offset,
		length - offset,
		&decoded_instruction,
		operands.data()
	))) {
		std::cout << "\n" << std::hex << runtime_address << " : ";
		for (ZyanU8 i = 0; i < decoded_instruction.length; ++i) {
			std::cout << std::setw(2) << std::setfill('0')
				<< static_cast<unsigned>(data[offset + i]) << " ";
		}
		// Format & print the binary instruction structure to human-readable format
		char buffer[256];
		ZydisFormatterFormatInstruction(
			&formatter,
			&decoded_instruction,
			operands.data(),
			decoded_instruction.operand_count_visible,
			buffer,
			sizeof(buffer),
			runtime_address,
			ZYAN_NULL
		);

		std::cout << " : " << buffer;

		offset += decoded_instruction.length;
		runtime_address += decoded_instruction.length;
		Sleep(500);

	}
}

void Disassembler::zDisassembler() {
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		runtime_address,
		data.data() + offset,
		sizeof(data.data()) - offset,
		&disass_instruction
	))) {
		printf("%016" PRIX64 "  %s\n", runtime_address, disass_instruction.text);
		offset += disass_instruction.info.length;
		runtime_address += disass_instruction.info.length;
		Sleep(500);
	}
}

} // namespace core
} // namespace lilemu
