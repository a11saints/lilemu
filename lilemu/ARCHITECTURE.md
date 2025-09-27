# Lilemu VMProtect Emulator - Modular Architecture

## Overview

The Lilemu VMProtect Emulator has been refactored from a monolithic `Source.cpp` file into a clean, modular architecture. This refactoring improves maintainability, testability, and extensibility while preserving all original functionality.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    LilemuEngine                            │
│                 (Main Controller)                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ PEParser    │ │MemoryManager│ │HookManager  │
│             │ │             │ │             │
└─────────────┘ └─────────────┘ └─────────────┘
        │             │             │
        ▼             ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│VMProtect    │ │  Emulator   │ │Disassembler │
│Detector     │ │             │ │             │
└─────────────┘ └─────────────┘ └─────────────┘
```

## Module Breakdown

### 1. Core Configuration (`Core/Config.hpp`, `Core/Config.cpp`)
**Purpose**: Centralized configuration management
- **MemoryLayout**: Memory addresses, sizes, and layout constants
- **EmulationConfig**: Emulation-specific settings
- **FileConfig**: File paths and names
- **LogConfig**: Logging configuration

**Benefits**:
- Single source of truth for all constants
- Easy to modify configuration without code changes
- Type-safe configuration access

### 2. PE Parser (`Core/PEParser.hpp`, `Core/PEParser.cpp`)
**Purpose**: PE file parsing and analysis
- **LoadPE()**: Load and parse PE files
- **ParseHeaders()**: Parse DOS and NT headers
- **ParseSections()**: Extract section information
- **RvaToRaw()/RawToRva()**: Address translation utilities
- **CheckModuleBoundaries()**: Memory boundary validation

**Benefits**:
- Clean separation of PE parsing logic
- Reusable across different parts of the system
- Comprehensive error handling

### 3. Memory Manager (`Core/MemoryManager.hpp`, `Core/MemoryManager.cpp`)
**Purpose**: Memory management and mapping
- **Initialize()**: Set up memory layout
- **MapPESections()**: Map PE sections to emulated memory
- **MapStack()**: Initialize stack memory
- **ReadMemory()/WriteMemory()**: Memory access operations
- **IsValidAddress()**: Memory validation

**Benefits**:
- Centralized memory management
- Clean abstraction over Unicorn memory operations
- Memory safety validation

### 4. Hook Manager (`Core/HookManager.hpp`, `Core/HookManager.cpp`)
**Purpose**: Emulation hook management and analysis
- **AddCodeHook()**: Add instruction execution hooks
- **AddMemoryHook()**: Add memory access hooks
- **AddCallHook()**: Specialized call instruction hooks
- **AddVMProtectHook()**: VMProtect-specific pattern detection
- **IsCallInstruction()**: Call instruction detection
- **IsVMProtectPattern()**: VMProtect pattern recognition

**Benefits**:
- Flexible hook system
- Specialized hooks for VMProtect analysis
- Clean callback management

### 5. VMProtect Detector (`Core/VMProtectDetector.hpp`, `Core/VMProtectDetector.cpp`)
**Purpose**: VMProtect protection detection and analysis
- **AnalyzeBinary()**: Comprehensive VMProtect analysis
- **FindPattern()**: Pattern matching with masks
- **DetectVersion()**: VMProtect version detection
- **FindVMEntryPoints()**: Locate VM entry points
- **FindVMHandlers()**: Locate VM handlers

**Benefits**:
- Specialized VMProtect detection
- Extensible pattern database
- Version-specific analysis

### 6. Main Engine (`Core/LilemuEngine.hpp`, `Core/LilemuEngine.cpp`)
**Purpose**: Main controller orchestrating all modules
- **Initialize()**: Initialize all components
- **LoadTarget()**: Load and prepare target binary
- **StartEmulation()**: Begin emulation process
- **AnalyzeTarget()**: Perform VMProtect analysis
- **Configure()**: Set engine parameters

**Benefits**:
- Single entry point for all operations
- Clean component lifecycle management
- Easy to use API

## Refactoring Benefits

### Before (Monolithic Source.cpp)
- ❌ 260+ lines of mixed responsibilities
- ❌ Global variables scattered throughout
- ❌ Hardcoded values and magic numbers
- ❌ Difficult to test individual components
- ❌ Poor separation of concerns
- ❌ Hard to extend or modify

### After (Modular Architecture)
- ✅ Clean separation of concerns
- ✅ No global variables
- ✅ Centralized configuration
- ✅ Testable components
- ✅ Extensible design
- ✅ Clear module boundaries
- ✅ Better error handling
- ✅ Improved maintainability

## Usage Example

```cpp
#include "Core/LilemuEngine.hpp"

int main() {
    // Create and configure engine
    auto engine = std::make_unique<LilemuEngine>();
    engine->SetLogLevel(spdlog::level::info);
    engine->EnableVMProtectDetection(true);
    
    // Initialize and load target
    engine->Initialize();
    engine->LoadTarget("target.exe");
    
    // Analyze and emulate
    engine->AnalyzeTarget();
    engine->StartEmulation();
    
    return 0;
}
```

## File Structure

```
lilemu/
├── Core/
│   ├── Config.hpp/cpp          # Configuration management
│   ├── PEParser.hpp/cpp        # PE file parsing
│   ├── MemoryManager.hpp/cpp   # Memory management
│   ├── HookManager.hpp/cpp     # Hook management
│   ├── VMProtectDetector.hpp/cpp # VMProtect detection
│   └── LilemuEngine.hpp/cpp    # Main engine controller
├── Source.cpp                  # Refactored main entry point
├── Emulator.hpp/cpp            # Unicorn emulator wrapper
├── Disassembler.hpp/cpp        # Zydis disassembler wrapper
└── ApiResolver.hpp/cpp         # API resolution utilities
```

## Future Enhancements

1. **Plugin System**: Allow dynamic loading of analysis modules
2. **Configuration Files**: Support for external configuration files
3. **Multi-threading**: Parallel analysis and emulation
4. **Advanced VMProtect Detection**: More sophisticated pattern recognition
5. **Export/Import**: Save and load analysis results
6. **GUI Interface**: Graphical user interface for the emulator

## Migration Notes

- All original functionality has been preserved
- Global variables have been eliminated
- Hardcoded values moved to configuration
- Error handling has been improved
- Logging has been standardized
- Memory management is now centralized

The refactored code maintains full backward compatibility while providing a much cleaner and more maintainable architecture.

