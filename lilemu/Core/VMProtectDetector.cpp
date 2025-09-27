#include "VMProtectDetector.hpp"
#include <algorithm>
#include <cstring>

namespace lilemu {
namespace core {

    VMProtectDetector::VMProtectDetector() {
        InitializePatterns();
    }

    VMProtectDetector::~VMProtectDetector() {
    }

    void VMProtectDetector::InitializePatterns() {
        knownPatterns_.clear();
        
        AddVMProtectV2Patterns();
        AddVMProtectV3Patterns();
        AddVMProtectV4Patterns();
        AddGenericPatterns();
        
        spdlog::info("Initialized {} VMProtect patterns", knownPatterns_.size());
    }

    void VMProtectDetector::AddVMProtectV2Patterns() {
        // VMProtect 2.x patterns
        VMProtectPattern pattern;
        
        // Pattern 1: VMProtect 2.x entry point
        pattern.name = "VMProtect_V2_Entry";
        pattern.pattern = {0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED};
        pattern.mask = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF};
        pattern.version = VMProtectVersion::V2;
        pattern.description = "VMProtect 2.x virtual machine entry point";
        knownPatterns_.push_back(pattern);
        
        // Pattern 2: VMProtect 2.x handler
        pattern.name = "VMProtect_V2_Handler";
        pattern.pattern = {0x8B, 0x44, 0x24, 0x04, 0x8B, 0x00, 0x8B, 0x40, 0x04};
        pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        pattern.version = VMProtectVersion::V2;
        pattern.description = "VMProtect 2.x virtual machine handler";
        knownPatterns_.push_back(pattern);
    }

    void VMProtectDetector::AddVMProtectV3Patterns() {
        // VMProtect 3.x patterns
        VMProtectPattern pattern;
        
        // Pattern 1: VMProtect 3.x entry point
        pattern.name = "VMProtect_V3_Entry";
        pattern.pattern = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x57};
        pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        pattern.version = VMProtectVersion::V3;
        pattern.description = "VMProtect 3.x virtual machine entry point";
        knownPatterns_.push_back(pattern);
        
        // Pattern 2: VMProtect 3.x handler
        pattern.name = "VMProtect_V3_Handler";
        pattern.pattern = {0x8B, 0x45, 0x08, 0x8B, 0x00, 0x8B, 0x40, 0x08, 0x89, 0x45, 0xFC};
        pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        pattern.version = VMProtectVersion::V3;
        pattern.description = "VMProtect 3.x virtual machine handler";
        knownPatterns_.push_back(pattern);
    }

    void VMProtectDetector::AddVMProtectV4Patterns() {
        // VMProtect 4.x patterns
        VMProtectPattern pattern;
        
        // Pattern 1: VMProtect 4.x entry point
        pattern.name = "VMProtect_V4_Entry";
        pattern.pattern = {0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00};
        pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};
        pattern.version = VMProtectVersion::V4;
        pattern.description = "VMProtect 4.x virtual machine entry point";
        knownPatterns_.push_back(pattern);
        
        // Pattern 2: VMProtect 4.x handler
        pattern.name = "VMProtect_V4_Handler";
        pattern.pattern = {0x48, 0x8B, 0x44, 0x24, 0x08, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x40, 0x08};
        pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        pattern.version = VMProtectVersion::V4;
        pattern.description = "VMProtect 4.x virtual machine handler";
        knownPatterns_.push_back(pattern);
    }

    void VMProtectDetector::AddGenericPatterns() {
        // Generic VMProtect patterns
        VMProtectPattern pattern;
        
        // Pattern 1: Common VMProtect magic values
        pattern.name = "VMProtect_Magic";
        pattern.pattern = {0xDE, 0xAD, 0xBE, 0xEF};
        pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF};
        pattern.version = VMProtectVersion::Unknown;
        pattern.description = "VMProtect magic value";
        knownPatterns_.push_back(pattern);
        
        // Pattern 2: VMProtect string signature
        pattern.name = "VMProtect_String";
        pattern.pattern = {'V', 'M', 'P', 'r', 'o', 't', 'e', 'c', 't'};
        pattern.mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        pattern.version = VMProtectVersion::Unknown;
        pattern.description = "VMProtect string signature";
        knownPatterns_.push_back(pattern);
    }

    VMProtectInfo VMProtectDetector::AnalyzeBinary(const std::vector<uint8_t>& binary, uint64_t baseAddress) {
        detectionResults_ = VMProtectInfo{};
        detectionResults_.isProtected = false;
        detectionResults_.version = VMProtectVersion::Unknown;

        spdlog::info("Starting VMProtect analysis on binary (size: 0x{:x})", binary.size());

        // Detect VMProtect protection
        if (DetectVMProtect(binary, baseAddress)) {
            detectionResults_.isProtected = true;
            detectionResults_.version = DetectVersion(binary);
            
            // Find VM entry points and handlers
            detectionResults_.vmEntryPoints = FindVMEntryPoints(binary);
            detectionResults_.vmHandlers = FindVMHandlers(binary);
            
            spdlog::info("VMProtect detected - Version: {}, Entry Points: {}, Handlers: {}", 
                        static_cast<int>(detectionResults_.version),
                        detectionResults_.vmEntryPoints.size(),
                        detectionResults_.vmHandlers.size());
        } else {
            spdlog::info("No VMProtect protection detected");
        }

        return detectionResults_;
    }

    bool VMProtectDetector::DetectVMProtect(const std::vector<uint8_t>& binary, uint64_t baseAddress) {
        // Check for known VMProtect patterns
        for (const auto& pattern : knownPatterns_) {
            auto matches = FindPattern(binary, pattern.pattern, pattern.mask);
            if (!matches.empty()) {
                detectionResults_.patterns[pattern.name] = matches;
                spdlog::info("Found pattern '{}' at {} locations", pattern.name, matches.size());
            }
        }

        // If we found any VMProtect patterns, consider it protected
        return !detectionResults_.patterns.empty();
    }

    std::vector<uint64_t> VMProtectDetector::FindPattern(const std::vector<uint8_t>& binary, 
                                                        const std::vector<uint8_t>& pattern,
                                                        const std::vector<uint8_t>& mask) {
        std::vector<uint64_t> matches;
        
        if (pattern.empty() || binary.size() < pattern.size()) {
            return matches;
        }

        size_t maskSize = mask.empty() ? pattern.size() : mask.size();
        if (maskSize != pattern.size()) {
            spdlog::warn("Pattern and mask size mismatch");
            return matches;
        }

        for (size_t i = 0; i <= binary.size() - pattern.size(); ++i) {
            if (MatchPattern(&binary[i], binary.size() - i, 
                           pattern.data(), mask.data(), pattern.size())) {
                matches.push_back(i);
            }
        }

        return matches;
    }

    bool VMProtectDetector::MatchPattern(const uint8_t* data, size_t dataSize,
                                        const uint8_t* pattern, const uint8_t* mask, size_t patternSize) {
        if (dataSize < patternSize) {
            return false;
        }

        for (size_t i = 0; i < patternSize; ++i) {
            if (mask[i] != 0xFF && (data[i] & mask[i]) != (pattern[i] & mask[i])) {
                return false;
            }
        }

        return true;
    }

    std::vector<uint64_t> VMProtectDetector::FindVMEntryPoints(const std::vector<uint8_t>& binary) {
        std::vector<uint64_t> entryPoints;
        
        // Look for common VM entry point patterns
        for (const auto& pattern : knownPatterns_) {
            if (pattern.name.find("Entry") != std::string::npos) {
                auto matches = FindPattern(binary, pattern.pattern, pattern.mask);
                entryPoints.insert(entryPoints.end(), matches.begin(), matches.end());
            }
        }

        return entryPoints;
    }

    std::vector<uint64_t> VMProtectDetector::FindVMHandlers(const std::vector<uint8_t>& binary) {
        std::vector<uint64_t> handlers;
        
        // Look for common VM handler patterns
        for (const auto& pattern : knownPatterns_) {
            if (pattern.name.find("Handler") != std::string::npos) {
                auto matches = FindPattern(binary, pattern.pattern, pattern.mask);
                handlers.insert(handlers.end(), matches.begin(), matches.end());
            }
        }

        return handlers;
    }

    VMProtectVersion VMProtectDetector::DetectVersion(const std::vector<uint8_t>& binary) {
        // Check for version-specific patterns
        for (const auto& pattern : knownPatterns_) {
            if (pattern.version != VMProtectVersion::Unknown) {
                auto matches = FindPattern(binary, pattern.pattern, pattern.mask);
                if (!matches.empty()) {
                    return pattern.version;
                }
            }
        }

        return VMProtectVersion::Unknown;
    }

    bool VMProtectDetector::IsVMProtectInstruction(const uint8_t* code, size_t size) {
        // Check if instruction matches VMProtect patterns
        for (const auto& pattern : knownPatterns_) {
            if (pattern.pattern.size() <= size) {
                if (MatchPattern(code, size, pattern.pattern.data(), 
                               pattern.mask.data(), pattern.pattern.size())) {
                    return true;
                }
            }
        }
        return false;
    }

    bool VMProtectDetector::IsVMProtectCall(const uint8_t* code, size_t size) {
        // Check for VMProtect-specific call patterns
        if (size < 2) return false;
        
        // Common VMProtect call patterns
        if (code[0] == 0xE8 && size >= 5) {
            // Check if the call target looks like a VMProtect handler
            int32_t rel = *reinterpret_cast<const int32_t*>(&code[1]);
            // Additional analysis could be done here
            return true;
        }
        
        return false;
    }

    bool VMProtectDetector::IsVMProtectJump(const uint8_t* code, size_t size) {
        // Check for VMProtect-specific jump patterns
        if (size < 2) return false;
        
        // Common VMProtect jump patterns
        if (code[0] == 0xE9 && size >= 5) {
            // Check if the jump target looks like a VMProtect handler
            int32_t rel = *reinterpret_cast<const int32_t*>(&code[1]);
            // Additional analysis could be done here
            return true;
        }
        
        return false;
    }

} // namespace core
} // namespace lilemu

