#pragma once
#include "IncludeMe.hpp"
#include "Config.hpp"
#include "Disassembler.hpp"
#include "Emulator.hpp"
#include <functional>
#include <vector>
#include <memory>

namespace lilemu {
namespace core {

    // Forward declarations
    class Emulator;
    class PEParser;

    // Hook callback types
    using CodeHookCallback = std::function<void(uc_engine*, uint64_t, uint32_t, void*)>;
    using MemoryHookCallback = std::function<void(uc_engine*, uc_mem_type, uint64_t, int, int64_t, void*)>;
    using InstructionHookCallback = std::function<void(uc_engine*, void*)>;

    struct HookInfo {
        uc_hook hook;
        int type;
        void* callback;
        void* userData;
        uint64_t start;
        uint64_t end;
        bool isActive;
    };

    class HookManager {
    public:
        HookManager(Emulator* emulator, PEParser* peParser, Disassembler* disassembler);
        ~HookManager();

        // Hook management
        bool AddCodeHook(uint64_t start, uint64_t end, CodeHookCallback callback, void* userData = nullptr);
        bool AddMemoryHook(uint64_t start, uint64_t end, MemoryHookCallback callback, void* userData = nullptr);
        bool AddInstructionHook(uint64_t start, uint64_t end, InstructionHookCallback callback, void* userData = nullptr);
        bool RemoveHook(uc_hook hook);
        void RemoveAllHooks();

        // Specific hook types for VMProtect analysis
        bool AddCallHook();
        bool AddMemoryAccessHook();
        bool AddSyscallHook();
        bool AddVMProtectHook();

        // Hook callbacks
        static void HookCodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* userData);
        static void HookMemoryCallback(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* userData);
        static void HookSyscallCallback(uc_engine* uc, void* userData);

        // Analysis functions
        bool IsCallInstruction(const uint8_t* code, size_t size);
        uint64_t ExtractCallAddress(const uint8_t* code, size_t size, uint64_t currentAddress);
        bool IsVMProtectPattern(const uint8_t* code, size_t size);

        // Get hook information
        const std::vector<HookInfo>& GetHooks() const { return hooks_; }
        size_t GetHookCount() const { return hooks_.size(); }

    private:
        Emulator* emulator_;
        PEParser* peParser_;
        Disassembler* disassembler_;
        
        std::vector<HookInfo> hooks_;
        std::vector<CodeHookCallback> codeCallbacks_;
        std::vector<MemoryHookCallback> memoryCallbacks_;
        std::vector<InstructionHookCallback> instructionCallbacks_;

        // Internal analysis
        void AnalyzeInstruction(uint64_t address, const uint8_t* code, size_t size);
        void LogInstruction(uint64_t address, const uint8_t* code, size_t size);
        bool CheckModuleBoundaries(uint64_t address);
    };

} // namespace core
} // namespace lilemu

