#pragma once
#include "IncludeMe.hpp"
#include "Config.hpp"
#include "PEParser.hpp"
#include <vector>
#include <memory>

namespace lilemu {
namespace core {

    class MemoryManager {
    public:
        MemoryManager();
        ~MemoryManager();

        // Initialize memory layout
        bool Initialize(const PEInfo& peInfo, const std::vector<uint8_t>& fileBuffer);
        
        // Memory operations
        void* AllocateMemory(size_t size, uint32_t permissions = UC_PROT_ALL);
        bool MapMemory(uint64_t address, uint64_t size, uint32_t permissions);
        bool UnmapMemory(uint64_t address, uint64_t size);
        
        // Memory access
        bool ReadMemory(uint64_t address, void* buffer, size_t size);
        bool WriteMemory(uint64_t address, const void* buffer, size_t size);
        
        // Section mapping
        bool MapPESections(const PEInfo& peInfo, const std::vector<uint8_t>& fileBuffer);
        bool MapStack();
        
        // Memory validation
        bool IsValidAddress(uint64_t address) const;
        bool IsInModuleBounds(uint64_t address) const;
        
        // Get memory information
        uint64_t GetBaseAddress() const { return baseAddress_; }
        uint64_t GetModuleSize() const { return moduleSize_; }
        uint64_t GetStackAddress() const { return stackAddress_; }
        uint64_t GetStackSize() const { return stackSize_; }

    private:
        bool InitializeStack();
        bool MapSection(const SectionInfo& section, const std::vector<uint8_t>& fileBuffer);
        
        uint64_t baseAddress_;
        uint64_t moduleSize_;
        uint64_t stackAddress_;
        uint64_t stackSize_;
        
        std::vector<uint8_t> stackBuffer_;
        std::vector<std::pair<uint64_t, uint64_t>> mappedRegions_;
        
        bool isInitialized_;
    };

} // namespace core
} // namespace lilemu

