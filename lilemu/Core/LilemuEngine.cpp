#include "LilemuEngine.hpp"
#include "Disassembler.hpp"
#include "Emulator.hpp"
#include <iostream>

namespace lilemu {
namespace core {

    LilemuEngine::LilemuEngine()
        : targetFile_(config::FileConfig::DEFAULT_TARGET_FILE)
        , enableVMProtectDetection_(true)
        , enableCallHooks_(true)
        , enableMemoryHooks_(false)
        , logLevel_(spdlog::level::info)
        , isInitialized_(false)
        , isRunning_(false)
    {
    }

    LilemuEngine::~LilemuEngine() {
        Shutdown();
    }

    bool LilemuEngine::Initialize() {
        if (isInitialized_) {
            spdlog::warn("Engine already initialized");
            return true;
        }

        spdlog::info("Initializing Lilemu Engine...");

        // Set logging level
        spdlog::set_level(logLevel_);

        // Initialize components
        if (!InitializeComponents()) {
            spdlog::error("Failed to initialize components");
            return false;
        }

        // Log system information
        LogSystemInfo();

        isInitialized_ = true;
        spdlog::info("Lilemu Engine initialized successfully");
        return true;
    }

    bool LilemuEngine::InitializeComponents() {
        try {
            // Initialize PE Parser
            peParser_ = std::make_unique<PEParser>();
            spdlog::debug("PE Parser initialized");

            // Initialize Memory Manager
            memoryManager_ = std::make_unique<MemoryManager>();
            spdlog::debug("Memory Manager initialized");

            // Initialize VMProtect Detector
            vmDetector_ = std::make_unique<VMProtectDetector>();
            spdlog::debug("VMProtect Detector initialized");

            return true;
        }
        catch (const std::exception& e) {
            spdlog::error("Exception during component initialization: {}", e.what());
            return false;
        }
    }

    bool LilemuEngine::LoadTarget(const std::string& filePath) {
        if (!isInitialized_) {
            spdlog::error("Engine not initialized");
            return false;
        }

        if (isRunning_) {
            spdlog::error("Cannot load target while emulation is running");
            return false;
        }

        spdlog::info("Loading target: {}", filePath);

        // Load PE file
        if (!peParser_->LoadPE(filePath)) {
            spdlog::error("Failed to load PE file");
            return false;
        }

        // Read file buffer for analysis
        if (!peParser_->ReadFile(fileBuffer_, filePath)) {
            spdlog::error("Failed to read file buffer");
            return false;
        }

        // Initialize memory manager with PE info
        if (!memoryManager_->Initialize(peParser_->GetPEInfo(), fileBuffer_)) {
            spdlog::error("Failed to initialize memory manager");
            return false;
        }

        // Initialize emulator
        emulator_ = std::make_unique<Emulator>(
            config::MemoryLayout::BASE_ADDR,
            config::MemoryLayout::CODE_SIZE,
            fileBuffer_,
            UC_ARCH_X86,
            UC_MODE_64
        );

        emulator_->init_uc();
        spdlog::debug("Emulator initialized");

        // Initialize disassembler
        ZyanU64 entryPoint = config::MemoryLayout::BASE_ADDR + peParser_->GetPEInfo().entryPoint;
        ZyanUSize rawEntry = peParser_->GetPEInfo().entryPoint;
        disassembler_ = std::make_unique<Disassembler>(
            entryPoint, 
            fileBuffer_, 
            rawEntry
        );
        spdlog::debug("Disassembler initialized");

        // Initialize hook manager
        hookManager_ = std::make_unique<HookManager>(emulator_.get(), peParser_.get(), disassembler_.get());
        spdlog::debug("Hook Manager initialized");

        // Setup hooks
        if (!SetupHooks()) {
            spdlog::error("Failed to setup hooks");
            return false;
        }

        // Analyze target if VMProtect detection is enabled
        if (enableVMProtectDetection_) {
            if (!AnalyzeTarget()) {
                spdlog::warn("VMProtect analysis failed, continuing...");
            }
        }

        spdlog::info("Target loaded successfully");
        return true;
    }

    bool LilemuEngine::SetupHooks() {
        if (!hookManager_) {
            spdlog::error("Hook manager not initialized");
            return false;
        }

        // Add call hooks if enabled
        if (enableCallHooks_) {
            if (!hookManager_->AddCallHook()) {
                spdlog::error("Failed to add call hooks");
                return false;
            }
        }

        // Add memory hooks if enabled
        if (enableMemoryHooks_) {
            if (!hookManager_->AddMemoryAccessHook()) {
                spdlog::error("Failed to add memory hooks");
                return false;
            }
        }

        // Add syscall hooks
        if (!hookManager_->AddSyscallHook()) {
            spdlog::error("Failed to add syscall hooks");
            return false;
        }

        // Add VMProtect detection hooks
        if (enableVMProtectDetection_) {
            if (!hookManager_->AddVMProtectHook()) {
                spdlog::error("Failed to add VMProtect hooks");
                return false;
            }
        }

        spdlog::info("Hooks setup successfully");
        return true;
    }

    bool LilemuEngine::StartEmulation() {
        if (!isInitialized_) {
            spdlog::error("Engine not initialized");
            return false;
        }

        if (isRunning_) {
            spdlog::warn("Emulation already running");
            return true;
        }

        if (!emulator_) {
            spdlog::error("Emulator not initialized");
            return false;
        }

        spdlog::info("Starting emulation...");

        // Get entry point
        uint64_t entryPoint = config::MemoryLayout::BASE_ADDR + peParser_->GetPEInfo().entryPoint;
        
        // Start emulation
        try {
            emulator_->emu_start(
                config::EmulationConfig::ENTRY_POINT_OFFSET,
                config::MemoryLayout::BASE_ADDR + config::MemoryLayout::CODE_SIZE - 
                (entryPoint - config::MemoryLayout::BASE_ADDR),
                0, 0
            );
            
            isRunning_ = true;
            spdlog::info("Emulation started successfully");
            return true;
        }
        catch (const std::exception& e) {
            spdlog::error("Exception during emulation start: {}", e.what());
            return false;
        }
    }

    bool LilemuEngine::StartEmulation(uint64_t entryPoint) {
        if (!isInitialized_) {
            spdlog::error("Engine not initialized");
            return false;
        }

        if (isRunning_) {
            spdlog::warn("Emulation already running");
            return true;
        }

        if (!emulator_) {
            spdlog::error("Emulator not initialized");
            return false;
        }

        spdlog::info("Starting emulation at entry point: 0x{:x}", entryPoint);

        try {
            emulator_->emu_start(
                entryPoint,
                config::MemoryLayout::BASE_ADDR + config::MemoryLayout::CODE_SIZE,
                0, 0
            );
            
            isRunning_ = true;
            spdlog::info("Emulation started successfully");
            return true;
        }
        catch (const std::exception& e) {
            spdlog::error("Exception during emulation start: {}", e.what());
            return false;
        }
    }

    void LilemuEngine::StopEmulation() {
        if (!isRunning_) {
            return;
        }

        spdlog::info("Stopping emulation...");
        
        // Stop emulation (this would need to be implemented in the Emulator class)
        // emulator_->stop();
        
        isRunning_ = false;
        spdlog::info("Emulation stopped");
    }

    bool LilemuEngine::AnalyzeTarget() {
        if (!vmDetector_ || fileBuffer_.empty()) {
            spdlog::error("VMProtect detector or file buffer not available");
            return false;
        }

        spdlog::info("Analyzing target for VMProtect protection...");
        
        auto vmInfo = vmDetector_->AnalyzeBinary(fileBuffer_, config::MemoryLayout::BASE_ADDR);
        
        if (vmInfo.isProtected) {
            spdlog::warn("VMProtect protection detected!");
            spdlog::info("Version: {}, Entry Points: {}, Handlers: {}", 
                        static_cast<int>(vmInfo.version),
                        vmInfo.vmEntryPoints.size(),
                        vmInfo.vmHandlers.size());
        } else {
            spdlog::info("No VMProtect protection detected");
        }

        return true;
    }

    void LilemuEngine::Shutdown() {
        if (isRunning_) {
            StopEmulation();
        }

        // Cleanup components
        hookManager_.reset();
        disassembler_.reset();
        emulator_.reset();
        vmDetector_.reset();
        memoryManager_.reset();
        peParser_.reset();

        isInitialized_ = false;
        spdlog::info("Lilemu Engine shutdown complete");
    }

    void LilemuEngine::SetTargetFile(const std::string& filePath) {
        targetFile_ = filePath;
    }

    void LilemuEngine::SetLogLevel(spdlog::level::level_enum level) {
        logLevel_ = level;
        spdlog::set_level(level);
    }

    void LilemuEngine::EnableVMProtectDetection(bool enable) {
        enableVMProtectDetection_ = enable;
    }

    void LilemuEngine::EnableCallHooks(bool enable) {
        enableCallHooks_ = enable;
    }

    void LilemuEngine::EnableMemoryHooks(bool enable) {
        enableMemoryHooks_ = enable;
    }

    const VMProtectInfo& LilemuEngine::GetVMProtectInfo() const {
        static VMProtectInfo empty;
        return vmDetector_ ? vmDetector_->GetDetectionResults() : empty;
    }

    const PEInfo& LilemuEngine::GetPEInfo() const {
        static PEInfo empty;
        return peParser_ ? peParser_->GetPEInfo() : empty;
    }

    void LilemuEngine::LogSystemInfo() {
        spdlog::info("=== Lilemu Engine System Information ===");
        spdlog::info("Target File: {}", targetFile_);
        spdlog::info("VMProtect Detection: {}", enableVMProtectDetection_ ? "Enabled" : "Disabled");
        spdlog::info("Call Hooks: {}", enableCallHooks_ ? "Enabled" : "Disabled");
        spdlog::info("Memory Hooks: {}", enableMemoryHooks_ ? "Enabled" : "Disabled");
        spdlog::info("Log Level: {}", spdlog::level::to_string_view(logLevel_));
        spdlog::info("========================================");
    }

} // namespace core
} // namespace lilemu

