#include <vector>
#include <stdio.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>

class Disassembler {
public:
	Disassembler(ZyanU64 runtime_address_, std::vector<ZyanU8>& data_) : runtime_address{ runtime_address_ }, data{ data_ } {
		Init();
	};

	int Init() {

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
	void Run() {
		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data.data() + offset, length - offset, &instruction, operands.data()))) {
			// Print current instruction pointer.
			printf("%016" PRIX64 "  ", runtime_address);
			// Format & print the binary instruction structure to human-readable format
			char buffer[256];
			ZydisFormatterFormatInstruction(
				&formatter,
				&instruction,
				operands.data(),
				instruction.operand_count_visible,
				buffer,
				sizeof(buffer),
				runtime_address,
				ZYAN_NULL
			);
			puts(buffer);

			offset += instruction.length;
			runtime_address += instruction.length;
		}
	}

private:
	ZydisDecoder decoder;
	ZydisFormatter formatter;
	ZydisDecodedInstruction instruction;
	std::vector<ZyanU8> data;
	std::vector< ZydisDecodedOperand> operands{ ZYDIS_MAX_OPERAND_COUNT };
	ZyanU64 runtime_address = 0;
	ZyanUSize offset = 0;
	const ZyanUSize length = 0;;
};


int main(void) {

	Disassembler ds();


    ZyanU8 data[] =
    {
        0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75,
        0x08, 0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F,
        0x88, 0xFC, 0xDA, 0x02, 0xc3,0xc3,0xc3,0xc3,0x90,0x90,0x90,0x90,0x00
    };

	std::vector<ZyanU8>* code = new std::vector<ZyanU8>();
	for (ZyanU8 byte : data) {
		 code->push_back(byte);
	}


    // The runtime address (instruction pointer) was chosen arbitrarily here in order to better
    // visualize relative addressing. In your actual program, set this to e.g. the memory address
    // that the code being disassembled was read from.
    ZyanU64 runtime_address = 0x007FFFFFFF400000;

    // Loop over the instructions in our buffer.
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
        /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
        /* runtime_address: */ runtime_address,
        /* buffer:          */ code->data() + offset,
        /* length:          */ sizeof(code->data()) - offset,
        /* instruction:     */ &instruction
    ))) {
        printf("%016" PRIX64 "  %s\n", runtime_address, instruction.text);
        offset += instruction.info.length;
        runtime_address += instruction.info.length;
    }

    return 0;
}