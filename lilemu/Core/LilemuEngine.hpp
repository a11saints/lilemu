#pragma once
#include "IncludeMe.hpp"
#include "Config.hpp"
#include "PEParser.hpp"
#include "MemoryManager.hpp"
#include "HookManager.hpp"
#include "VMProtectDetector.hpp"
#include "Emulator.hpp"
#include "Disassembler.hpp"
#include <memory>
#include <string>

namespace lilemu {
namespace core {

    class LilemuEngine {
    public:
        LilemuEngine();
        ~LilemuEngine();

        // Initialization
        bool Initialize();
        bool LoadTarget(const std::string& filePath);
        void Shutdown();

        // Main execution
        bool StartEmulation();
        bool StartEmulation(uint64_t entryPoint);
        void StopEmulation();

        // Configuration
        void SetTargetFile(const std::string& filePath);
        void SetLogLevel(spdlog::level::level_enum level);
        void EnableVMProtectDetection(bool enable);
        void EnableCallHooks(bool enable);
        void EnableMemoryHooks(bool enable);

        // Analysis
        bool AnalyzeTarget();
        const VMProtectInfo& GetVMProtectInfo() const;
        const PEInfo& GetPEInfo() const;

        // Status
        bool IsInitialized() const { return isInitialized_; }
        bool IsRunning() const { return isRunning_; }
        const std::string& GetTargetFile() const { return targetFile_; }

        // Getters for components
        PEParser* GetPEParser() { return peParser_.get(); }
        MemoryManager* GetMemoryManager() { return memoryManager_.get(); }
        HookManager* GetHookManager() { return hookManager_.get(); }
        VMProtectDetector* GetVMProtectDetector() { return vmDetector_.get(); }
        Emulator* GetEmulator() { return emulator_.get(); }
        Disassembler* GetDisassembler() { return disassembler_.get(); }

    private:
        // Core components
        std::unique_ptr<PEParser> peParser_;
        std::unique_ptr<MemoryManager> memoryManager_;
        std::unique_ptr<HookManager> hookManager_;
        std::unique_ptr<VMProtectDetector> vmDetector_;
        std::unique_ptr<Emulator> emulator_;
        std::unique_ptr<Disassembler> disassembler_;

        // Configuration
        std::string targetFile_;
        bool enableVMProtectDetection_;
        bool enableCallHooks_;
        bool enableMemoryHooks_;
        spdlog::level::level_enum logLevel_;

        // State
        bool isInitialized_;
        bool isRunning_;
        std::vector<ZyanU8> fileBuffer_;

        // Internal methods
        bool InitializeComponents();
        bool SetupHooks();
        bool SetupEmulation();
        void LogSystemInfo();
    };

} // namespace core
} // namespace lilemu

