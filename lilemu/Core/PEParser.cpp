#include "PEParser.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <Psapi.h>

namespace lilemu {
namespace core {

    PEParser::PEParser() 
        : peModule_(nullptr)
        , isValid_(false)
        , dosHeader_(nullptr)
        , ntHeaders_(nullptr)
        , sectionHeaders_(nullptr)
    {
    }

    PEParser::~PEParser() {
        if (peModule_) {
            FreeLibrary(peModule_);
        }
    }

    bool PEParser::LoadPE(const std::string& filePath) {
        // Read file into buffer
        if (!ReadFile(fileBuffer_, filePath)) {
            spdlog::error("Failed to read PE file: {}", filePath);
            return false;
        }

        // Load as module for additional operations
        peModule_ = LoadLibraryA(filePath.c_str());
        if (!peModule_) {
            spdlog::warn("Failed to load PE as module, continuing with buffer only");
        }

        return ParseHeaders() && ParseSections();
    }

    bool PEParser::LoadPE(HMODULE module) {
        peModule_ = module;
        
        // Get module information
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(modInfo))) {
            peInfo_.imageBase = reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
            peInfo_.imageSize = modInfo.SizeOfImage;
        }

        // Read module data into buffer
        fileBuffer_.resize(peInfo_.imageSize);
        memcpy(fileBuffer_.data(), modInfo.lpBaseOfDll, peInfo_.imageSize);

        return ParseHeaders() && ParseSections();
    }

    bool PEParser::ReadFile(std::vector<uint8_t>& buffer, const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file) {
            spdlog::error("Failed to open file: {}", filePath);
            return false;
        }

        std::streamsize size = file.tellg();
        if (size < 0) {
            spdlog::error("Failed to get file size");
            return false;
        }

        file.seekg(0, std::ios::beg);
        buffer.resize(static_cast<std::size_t>(size) + 0x1000); // Reserve extra space
        
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            spdlog::error("Failed to read file data");
            return false;
        }

        return true;
    }

    bool PEParser::ParseHeaders() {
        if (fileBuffer_.size() < sizeof(IMAGE_DOS_HEADER)) {
            spdlog::error("File too small to contain DOS header");
            return false;
        }

        dosHeader_ = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer_.data());
        if (dosHeader_->e_magic != IMAGE_DOS_SIGNATURE) {
            spdlog::error("Invalid DOS signature");
            return false;
        }

        if (fileBuffer_.size() < dosHeader_->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
            spdlog::error("File too small to contain NT headers");
            return false;
        }

        ntHeaders_ = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            fileBuffer_.data() + dosHeader_->e_lfanew);
        
        if (ntHeaders_->Signature != IMAGE_NT_SIGNATURE) {
            spdlog::error("Invalid NT signature");
            return false;
        }

        // Extract PE information
        peInfo_.imageBase = ntHeaders_->OptionalHeader.ImageBase;
        peInfo_.imageSize = ntHeaders_->OptionalHeader.SizeOfImage;
        peInfo_.entryPoint = ntHeaders_->OptionalHeader.AddressOfEntryPoint;

        sectionHeaders_ = IMAGE_FIRST_SECTION(ntHeaders_);
        isValid_ = true;

        spdlog::info("PE parsed successfully - Base: 0x{:x}, Size: 0x{:x}, Entry: 0x{:x}", 
                    peInfo_.imageBase, peInfo_.imageSize, peInfo_.entryPoint);

        return true;
    }

    bool PEParser::ParseSections() {
        if (!isValid_ || !sectionHeaders_) {
            return false;
        }

        peInfo_.sections.clear();
        peInfo_.sections.reserve(ntHeaders_->FileHeader.NumberOfSections);

        for (int i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
            const auto& sec = sectionHeaders_[i];
            
            SectionInfo section;
            section.name = std::string(reinterpret_cast<const char*>(sec.Name), 8);
            // Remove null terminator if present
            section.name.erase(std::find(section.name.begin(), section.name.end(), '\0'), section.name.end());
            
            section.virtualAddress = sec.VirtualAddress;
            section.virtualSize = sec.Misc.VirtualSize;
            section.rawAddress = sec.PointerToRawData;
            section.rawSize = sec.SizeOfRawData;
            section.characteristics = sec.Characteristics;

            peInfo_.sections.push_back(section);
        }

        BuildSectionMap();
        return true;
    }

    void PEParser::BuildSectionMap() {
        peInfo_.sectionMap.clear();
        
        for (const auto& section : peInfo_.sections) {
            peInfo_.sectionMap[section.name] = {
                section.virtualAddress,
                section.virtualAddress + section.virtualSize
            };
        }
    }

    const SectionInfo* PEParser::GetSection(const std::string& name) const {
        for (const auto& section : peInfo_.sections) {
            if (section.name == name) {
                return &section;
            }
        }
        return nullptr;
    }

    uint64_t PEParser::RvaToRaw(uint64_t rva) const {
        if (!isValid_ || !sectionHeaders_) {
            return 0;
        }

        for (int i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
            const auto& sec = sectionHeaders_[i];
            if (rva >= sec.VirtualAddress && 
                rva < sec.VirtualAddress + sec.Misc.VirtualSize) {
                return sec.PointerToRawData + (rva - sec.VirtualAddress);
            }
        }
        return 0;
    }

    uint64_t PEParser::RawToRva(uint64_t raw) const {
        if (!isValid_ || !sectionHeaders_) {
            return 0;
        }

        for (int i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
            const auto& sec = sectionHeaders_[i];
            if (raw >= sec.PointerToRawData && 
                raw < sec.PointerToRawData + sec.SizeOfRawData) {
                return sec.VirtualAddress + (raw - sec.PointerToRawData);
            }
        }
        return 0;
    }

    bool PEParser::CheckModuleBoundaries(uint64_t address) const {
        if (!isValid_) {
            return false;
        }

        uint64_t moduleEnd = peInfo_.imageBase + peInfo_.imageSize;
        return address >= peInfo_.imageBase && address < moduleEnd;
    }

} // namespace core
} // namespace lilemu

