#pragma once
#include "IncludeMe.hpp"
#include "Config.hpp"
#include <map>
#include <vector>
#include <string>
#include <memory>

namespace lilemu {
namespace core {

    struct SectionInfo {
        std::string name;
        uint64_t virtualAddress;
        uint64_t virtualSize;
        uint64_t rawAddress;
        uint64_t rawSize;
        uint32_t characteristics;
    };

    struct PEInfo {
        uint64_t imageBase;
        uint64_t imageSize;
        uint64_t entryPoint;
        std::vector<SectionInfo> sections;
        std::map<std::string, std::pair<uint64_t, uint64_t>> sectionMap;
    };

    class PEParser {
    public:
        PEParser();
        ~PEParser();

        // Load and parse PE file
        bool LoadPE(const std::string& filePath);
        bool LoadPE(HMODULE module);
        
        // Get PE information
        const PEInfo& GetPEInfo() const { return peInfo_; }
        bool IsValidPE() const { return isValid_; }
        
        // Section operations
        const SectionInfo* GetSection(const std::string& name) const;
        uint64_t RvaToRaw(uint64_t rva) const;
        uint64_t RawToRva(uint64_t raw) const;
        
        // File operations
        bool ReadFile(std::vector<uint8_t>& buffer, const std::string& filePath);
        bool CheckModuleBoundaries(uint64_t address) const;

    private:
        bool ParseHeaders();
        bool ParseSections();
        void BuildSectionMap();
        
        PEInfo peInfo_;
        std::vector<uint8_t> fileBuffer_;
        HMODULE peModule_;
        bool isValid_;
        
        // PE headers
        PIMAGE_DOS_HEADER dosHeader_;
        PIMAGE_NT_HEADERS64 ntHeaders_;
        PIMAGE_SECTION_HEADER sectionHeaders_;
    };

} // namespace core
} // namespace lilemu

