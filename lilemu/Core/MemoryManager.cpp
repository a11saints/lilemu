#include "MemoryManager.hpp"
#include <algorithm>
#include <cstring>

namespace lilemu {
namespace core {

    MemoryManager::MemoryManager()
        : baseAddress_(0)
        , moduleSize_(0)
        , stackAddress_(config::MemoryLayout::STACK_ADDRESS)
        , stackSize_(config::MemoryLayout::STACK_SIZE)
        , isInitialized_(false)
    {
    }

    MemoryManager::~MemoryManager() {
        // Cleanup is handled by the emulator
    }

    bool MemoryManager::Initialize(const PEInfo& peInfo, const std::vector<uint8_t>& fileBuffer) {
        baseAddress_ = config::MemoryLayout::BASE_ADDR;
        moduleSize_ = peInfo.imageSize;
        
        spdlog::info("Initializing memory manager - Base: 0x{:x}, Size: 0x{:x}", 
                    baseAddress_, moduleSize_);

        // Map PE sections
        if (!MapPESections(peInfo, fileBuffer)) {
            spdlog::error("Failed to map PE sections");
            return false;
        }

        // Initialize stack
        if (!MapStack()) {
            spdlog::error("Failed to initialize stack");
            return false;
        }

        isInitialized_ = true;
        spdlog::info("Memory manager initialized successfully");
        return true;
    }

    bool MemoryManager::MapPESections(const PEInfo& peInfo, const std::vector<uint8_t>& fileBuffer) {
        for (const auto& section : peInfo.sections) {
            if (!MapSection(section, fileBuffer)) {
                spdlog::error("Failed to map section: {}", section.name);
                return false;
            }
        }
        return true;
    }

    bool MemoryManager::MapSection(const SectionInfo& section, const std::vector<uint8_t>& fileBuffer) {
        uint64_t virtAddr = baseAddress_ + section.virtualAddress;
        uint64_t sizeToMap = section.rawSize > section.virtualSize ? section.rawSize : section.virtualSize;
        
        // Align to page boundary
        sizeToMap = (sizeToMap + 0xFFF) & ~0xFFF;

        // Map the section
        if (!MapMemory(virtAddr, sizeToMap, UC_PROT_ALL)) {
            spdlog::error("Failed to map section {} at 0x{:x}", section.name, virtAddr);
            return false;
        }

        // Write section data if it has raw data
        if (section.rawSize > 0) {
            if (section.rawAddress + section.rawSize > fileBuffer.size()) {
                spdlog::error("Section {} raw data out of bounds", section.name);
                return false;
            }
            
            if (!WriteMemory(virtAddr, fileBuffer.data() + section.rawAddress, section.rawSize)) {
                spdlog::error("Failed to write section {} data", section.name);
                return false;
            }
        }

        spdlog::info("Mapped section {} at 0x{:x} size 0x{:x}", 
                    section.name, virtAddr, sizeToMap);
        
        mappedRegions_.emplace_back(virtAddr, virtAddr + sizeToMap);
        return true;
    }

    bool MemoryManager::MapStack() {
        if (!MapMemory(stackAddress_, stackSize_, UC_PROT_ALL)) {
            spdlog::error("Failed to map stack memory");
            return false;
        }

        // Initialize stack buffer
        stackBuffer_.resize(stackSize_);
        std::memset(stackBuffer_.data(), config::MemoryLayout::STACK_INIT_VALUE, stackSize_);

        if (!WriteMemory(stackAddress_, stackBuffer_.data(), stackSize_)) {
            spdlog::error("Failed to initialize stack memory");
            return false;
        }

        spdlog::info("Stack mapped at 0x{:x} size 0x{:x}", stackAddress_, stackSize_);
        mappedRegions_.emplace_back(stackAddress_, stackAddress_ + stackSize_);
        return true;
    }

    bool MemoryManager::MapMemory(uint64_t address, uint64_t size, uint32_t permissions) {
        // This is a placeholder - actual implementation would use Unicorn's memory mapping
        // The real implementation would be in the Emulator class
        spdlog::debug("Mapping memory at 0x{:x} size 0x{:x} permissions 0x{:x}", 
                     address, size, permissions);
        return true;
    }

    bool MemoryManager::UnmapMemory(uint64_t address, uint64_t size) {
        // Remove from tracked regions
        auto it = std::find_if(mappedRegions_.begin(), mappedRegions_.end(),
            [address, size](const auto& region) {
                return region.first == address && region.second == address + size;
            });
        
        if (it != mappedRegions_.end()) {
            mappedRegions_.erase(it);
        }

        spdlog::debug("Unmapping memory at 0x{:x} size 0x{:x}", address, size);
        return true;
    }

    bool MemoryManager::ReadMemory(uint64_t address, void* buffer, size_t size) {
        if (!IsValidAddress(address)) {
            spdlog::warn("Invalid read address: 0x{:x}", address);
            return false;
        }

        // This is a placeholder - actual implementation would use Unicorn's memory read
        spdlog::debug("Reading memory at 0x{:x} size 0x{:x}", address, size);
        return true;
    }

    bool MemoryManager::WriteMemory(uint64_t address, const void* buffer, size_t size) {
        if (!IsValidAddress(address)) {
            spdlog::warn("Invalid write address: 0x{:x}", address);
            return false;
        }

        // This is a placeholder - actual implementation would use Unicorn's memory write
        spdlog::debug("Writing memory at 0x{:x} size 0x{:x}", address, size);
        return true;
    }

    bool MemoryManager::IsValidAddress(uint64_t address) const {
        if (!isInitialized_) {
            return false;
        }

        // Check if address is in any mapped region
        for (const auto& region : mappedRegions_) {
            if (address >= region.first && address < region.second) {
                return true;
            }
        }
        return false;
    }

    bool MemoryManager::IsInModuleBounds(uint64_t address) const {
        if (!isInitialized_) {
            return false;
        }

        return address >= baseAddress_ && address < baseAddress_ + moduleSize_;
    }

    void* MemoryManager::AllocateMemory(size_t size, uint32_t permissions) {
        // This would typically allocate memory in the emulator's address space
        spdlog::debug("Allocating memory size 0x{:x} permissions 0x{:x}", size, permissions);
        return nullptr; // Placeholder
    }

} // namespace core
} // namespace lilemu

