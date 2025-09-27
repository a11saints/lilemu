#include "HookManager.hpp"
#include "Emulator.hpp"
#include "PEParser.hpp"
#include <format>

namespace lilemu {
namespace core {

    HookManager::HookManager(Emulator* emulator, PEParser* peParser, Disassembler* disassembler)
        : emulator_(emulator)
        , peParser_(peParser)
        , disassembler_(disassembler)
    {
    }

    HookManager::~HookManager() {
        RemoveAllHooks();
    }

    bool HookManager::AddCodeHook(uint64_t start, uint64_t end, CodeHookCallback callback, void* userData) {
        if (!emulator_) {
            spdlog::error("Emulator not initialized");
            return false;
        }

        HookInfo hookInfo;
        hookInfo.type = UC_HOOK_CODE;
        hookInfo.callback = reinterpret_cast<void*>(HookCodeCallback);
        hookInfo.userData = userData;
        hookInfo.start = start;
        hookInfo.end = end;
        hookInfo.isActive = false;

        // Store callback for later use
        codeCallbacks_.push_back(callback);

        // Add hook to emulator

        emulator_->hook_add(&hookInfo.hook, hookInfo.type, hookInfo.callback, 
                           hookInfo.userData, hookInfo.start, hookInfo.end);

        hookInfo.isActive = true;
        hooks_.push_back(hookInfo);

        spdlog::info("Added code hook: 0x{:x} - 0x{:x}", start, end);
        return true;
    }

    bool HookManager::AddMemoryHook(uint64_t start, uint64_t end, MemoryHookCallback callback, void* userData) {
        if (!emulator_) {
            spdlog::error("Emulator not initialized");
            return false;
        }

        HookInfo hookInfo;
        hookInfo.type = UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE;
        hookInfo.callback = reinterpret_cast<void*>(HookMemoryCallback);
        hookInfo.userData = userData;
        hookInfo.start = start;
        hookInfo.end = end;
        hookInfo.isActive = false;

        // Store callback for later use
        memoryCallbacks_.push_back(callback);

        // Add hook to emulator
        emulator_->hook_add(&hookInfo.hook, hookInfo.type, hookInfo.callback, 
                           hookInfo.userData, hookInfo.start, hookInfo.end);

        hookInfo.isActive = true;
        hooks_.push_back(hookInfo);

        spdlog::info("Added memory hook: 0x{:x} - 0x{:x}", start, end);
        return true;
    }

    bool HookManager::AddInstructionHook(uint64_t start, uint64_t end, InstructionHookCallback callback, void* userData) {
        if (!emulator_) {
            spdlog::error("Emulator not initialized");
            return false;
        }

        HookInfo hookInfo;
        hookInfo.type = UC_HOOK_INSN;
        hookInfo.callback = reinterpret_cast<void*>(HookSyscallCallback);
        hookInfo.userData = userData;
        hookInfo.start = start;
        hookInfo.end = end;
        hookInfo.isActive = false;

        // Store callback for later use
        instructionCallbacks_.push_back(callback);

        // Add hook to emulator
        emulator_->hook_add(&hookInfo.hook, hookInfo.type, hookInfo.callback, 
                           hookInfo.userData, hookInfo.start, hookInfo.end);

        hookInfo.isActive = true;
        hooks_.push_back(hookInfo);

        spdlog::info("Added instruction hook: 0x{:x} - 0x{:x}", start, end);
        return true;
    }

    bool HookManager::AddCallHook() {
        return AddCodeHook(0, 0, [this](uc_engine* uc, uint64_t address, uint32_t size, void* userData) {
            uint8_t code[16];
            emulator_->mem_read(address, code, size);
            
            if (IsCallInstruction(code, size)) {
                uint64_t callAddress = ExtractCallAddress(code, size, address);
                if (callAddress != 0) {
                    spdlog::info("Call detected at 0x{:x} -> 0x{:x}", address, callAddress);
                    
                    if (!CheckModuleBoundaries(callAddress)) {
                        spdlog::warn("Call outside module boundaries: 0x{:x}", callAddress);
                    }
                }
            }
        });
    }

    bool HookManager::AddMemoryAccessHook() {
        return AddMemoryHook(0, 0, [this](uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* userData) {
            const char* accessType = (type == UC_MEM_READ) ? "READ" : "WRITE";
            spdlog::debug("Memory {} at 0x{:x} size {} value 0x{:x}", accessType, addr, size, value);
        });
    }

    bool HookManager::AddSyscallHook() {
        return AddInstructionHook(0, 0, [this](uc_engine* uc, void* userData) {
            uint64_t rax;
            emulator_->reg_read(UC_X86_REG_RAX, &rax);
            spdlog::info("Syscall detected: RAX = 0x{:x}", rax);
        });
    }

    bool HookManager::AddVMProtectHook() {
        return AddCodeHook(0, 0, [this](uc_engine* uc, uint64_t address, uint32_t size, void* userData) {
            uint8_t code[16];
            emulator_->mem_read(address, code, size);
            
            if (IsVMProtectPattern(code, size)) {
                spdlog::warn("VMProtect pattern detected at 0x{:x}", address);
            }
        });
    }

    void HookManager::HookCodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* userData) {
        // This is a static callback that will be called by Unicorn
        // We need to get the HookManager instance and call the appropriate callback
        // For now, this is a placeholder implementation
        spdlog::debug("Code hook triggered at 0x{:x} size {}", address, size);
    }

    void HookManager::HookMemoryCallback(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* userData) {
        // Static callback for memory hooks
        spdlog::debug("Memory hook triggered at 0x{:x}", addr);
    }

    void HookManager::HookSyscallCallback(uc_engine* uc, void* userData) {
        // Static callback for syscall hooks
        spdlog::debug("Syscall hook triggered");
    }

    bool HookManager::IsCallInstruction(const uint8_t* code, size_t size) {
        if (size < 2) return false;
        
        // Check for various call instruction patterns
        if (code[0] == 0xFF && code[1] == 0x15) return true; // call [rip+disp32]
        if (code[0] == 0xE8) return true; // call rel32
        if (code[0] == 0x9A) return true; // call far
        
        return false;
    }

    uint64_t HookManager::ExtractCallAddress(const uint8_t* code, size_t size, uint64_t currentAddress) {
        if (size < 2) return 0;

        if (code[0] == 0xFF && code[1] == 0x15) {
            // call [rip+disp32]
            if (size < 6) return 0;
            int32_t disp = *reinterpret_cast<const int32_t*>(&code[2]);
            return currentAddress + 6 + disp;
        }
        else if (code[0] == 0xE8) {
            // call rel32
            if (size < 5) return 0;
            int32_t rel = *reinterpret_cast<const int32_t*>(&code[1]);
            return currentAddress + 5 + rel;
        }

        return 0;
    }

    bool HookManager::IsVMProtectPattern(const uint8_t* code, size_t size) {
        // Common VMProtect patterns
        // This is a simplified detection - real implementation would be more sophisticated
        
        // Pattern 1: push/pop with unusual register combinations
        if (size >= 2 && code[0] == 0x50 && code[1] == 0x58) return true; // push rax; pop rax
        
        // Pattern 2: mov with immediate values that look like VMProtect constants
        if (size >= 7 && code[0] == 0x48 && code[1] == 0xB8) {
            uint64_t imm = *reinterpret_cast<const uint64_t*>(&code[2]);
            // Check for common VMProtect magic values
            if (imm == 0xDEADBEEF || imm == 0xCAFEBABE) return true;
        }

        return false;
    }

    void HookManager::AnalyzeInstruction(uint64_t address, const uint8_t* code, size_t size) {
        // Perform instruction analysis
        std::vector<uint8_t> bytes(code, code + size);
        ZydisDisassembledInstruction instruction;
        
        if (disassembler_) {
            disassembler_->Disass(address, bytes, 0, instruction);
            LogInstruction(address, code, size);
        }
    }

    void HookManager::LogInstruction(uint64_t address, const uint8_t* code, size_t size) {
        std::string hexBytes;
        for (size_t i = 0; i < size; ++i) {
            if (i != 0) hexBytes += " ";
            hexBytes += std::format("{:02x}", code[i]);
        }

        spdlog::info("0x{:x} | {} | {}", address, hexBytes, "disassembly");
    }

    bool HookManager::CheckModuleBoundaries(uint64_t address) {
        if (!peParser_) return true;
        return peParser_->CheckModuleBoundaries(address);
    }

    bool HookManager::RemoveHook(uc_hook hook) {
        auto it = std::find_if(hooks_.begin(), hooks_.end(),
            [hook](const HookInfo& info) { return info.hook == hook; });

        if (it != hooks_.end()) {
            it->isActive = false;
            hooks_.erase(it);
            spdlog::info("Removed hook");
            return true;
        }
        return false;
    }

    void HookManager::RemoveAllHooks() {
        for (auto& hook : hooks_) {
            hook.isActive = false;
        }
        hooks_.clear();
        codeCallbacks_.clear();
        memoryCallbacks_.clear();
        instructionCallbacks_.clear();
        spdlog::info("Removed all hooks");
    }

} // namespace core
} // namespace lilemu

