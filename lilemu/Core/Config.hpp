#pragma once
#include <string>
#include <cstdint>

namespace lilemu {
    namespace config {

        // Type aliases for better readability
        using u64 = uint64_t;
        using u32 = uint32_t;
        using u16 = uint16_t;
        using u8 = uint8_t;

        // Memory layout constants
        struct  MemoryLayout {
            static constexpr u64 BASE_ADDR = 0x0000000140000000;
            static constexpr u64 RVA_TEXT = 0x1000;
            static constexpr u64 RAW_TEXT = 0x400;
            static constexpr u64 RVA_DELTA = RVA_TEXT - RAW_TEXT;
            static constexpr u64 CODE_SIZE = 0x00241000;
            static constexpr u64 STACK_ADDRESS = 0x0;
            static constexpr u64 STACK_SIZE = 1024 * 1024;
            static constexpr u8 STACK_INIT_VALUE = 0xFF;
        };

        // Emulation constants
        struct  EmulationConfig {
            static constexpr u64 EXECUTE_INSTRUCTION_MAX = 0x40000;
            static constexpr u64 ENTRY_POINT_OFFSET = 0x0000001400010A0;
        };

        // File paths and names
        struct FileConfig {
        
            static const std::string DEFAULT_TARGET_FILE;
            static const std::string LOG_FILE;
        };

        // Logging configuration
        struct LogConfig {
            static constexpr bool ENABLE_DEBUG_LOGGING = true;
            static constexpr bool ENABLE_TRACE_LOGGING = false;
        };

    } // namespace config
} // namespace lilemu

