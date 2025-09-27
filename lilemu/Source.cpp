#include "Core/LilemuEngine.hpp"
#include "Core/Config.hpp"
#include <string>
#include <memory>

using namespace lilemu::core;

int main() {

    spdlog::info("=== Lilemu VMProtect Emulator ===");
    spdlog::info("Starting VMProtect emulation engine...");

    try {
        auto engine = std::make_unique<LilemuEngine>();
        
        engine->SetLogLevel(spdlog::level::info);
        engine->EnableVMProtectDetection(true);
        engine->EnableCallHooks(true);
        engine->EnableMemoryHooks(false);
        
        if (!engine->Initialize()) {
            spdlog::error("Failed to initialize Lilemu Engine");
            return -1;
        }

        std::string targetFile = lilemu::config::FileConfig::DEFAULT_TARGET_FILE;
        if (!engine->LoadTarget(targetFile)) {
            spdlog::error("Failed to load target file: {}", targetFile);
            return -1;
        }

        // Analyze the target for VMProtect protection
        if (!engine->AnalyzeTarget()) {
            spdlog::warn("VMProtect analysis failed, continuing...");
        }

        // Start emulation
        spdlog::info("Starting emulation...");
        if (!engine->StartEmulation()) {
            spdlog::error("Failed to start emulation");
            return -1;
        }

        // Keep the program running
        spdlog::info("Emulation started. Press Ctrl+C to stop...");
        Sleep(50000); // Keep running for 50 seconds

        // Stop emulation
        engine->StopEmulation();
        spdlog::info("Emulation stopped");

    }
    catch (const std::exception& e) {
        spdlog::error("Exception in main: {}", e.what());
        return -1;
    }

    spdlog::info("Lilemu Engine shutdown complete");
    return 0;
}

