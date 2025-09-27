#pragma once
#include "IncludeMe.hpp"
#include "Config.hpp"
#include <vector>
#include <string>
#include <map>

namespace lilemu {
namespace core {

    enum class VMProtectVersion {
        Unknown,
        V2,
        V3,
        V4
    };

    struct VMProtectPattern {
        std::string name;
        std::vector<uint8_t> pattern;
        std::vector<uint8_t> mask;
        VMProtectVersion version;
        std::string description;
    };

    struct VMProtectInfo {
        bool isProtected;
        VMProtectVersion version;
        std::vector<uint64_t> vmEntryPoints;
        std::vector<uint64_t> vmHandlers;
        std::map<std::string, std::vector<uint64_t>> patterns;
    };

    class VMProtectDetector {
    public:
        VMProtectDetector();
        ~VMProtectDetector();

        // Main detection function
        VMProtectInfo AnalyzeBinary(const std::vector<uint8_t>& binary, uint64_t baseAddress);
        
        // Pattern matching
        std::vector<uint64_t> FindPattern(const std::vector<uint8_t>& binary, 
                                         const std::vector<uint8_t>& pattern,
                                         const std::vector<uint8_t>& mask = {});
        
        // VMProtect specific patterns
        bool DetectVMProtect(const std::vector<uint8_t>& binary, uint64_t baseAddress);
        std::vector<uint64_t> FindVMEntryPoints(const std::vector<uint8_t>& binary);
        std::vector<uint64_t> FindVMHandlers(const std::vector<uint8_t>& binary);
        
        // Version detection
        VMProtectVersion DetectVersion(const std::vector<uint8_t>& binary);
        
        // Analysis functions
        bool IsVMProtectInstruction(const uint8_t* code, size_t size);
        bool IsVMProtectCall(const uint8_t* code, size_t size);
        bool IsVMProtectJump(const uint8_t* code, size_t size);
        
        // Get detection results
        const VMProtectInfo& GetDetectionResults() const { return detectionResults_; }
        const std::vector<VMProtectPattern>& GetKnownPatterns() const { return knownPatterns_; }

    private:
        void InitializePatterns();
        bool MatchPattern(const uint8_t* data, size_t dataSize,
                         const uint8_t* pattern, const uint8_t* mask, size_t patternSize);
        
        VMProtectInfo detectionResults_;
        std::vector<VMProtectPattern> knownPatterns_;
        
        // Common VMProtect signatures
        void AddVMProtectV2Patterns();
        void AddVMProtectV3Patterns();
        void AddVMProtectV4Patterns();
        void AddGenericPatterns();
    };

} // namespace core
} // namespace lilemu

