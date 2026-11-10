// ============================================================================
// pattern_scan.hpp - Zero-Dependency Memory Pattern / Signature Scanner
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Fast IDA-style byte pattern scanner (? and ?? wildcards) for PE binaries.
// ============================================================================

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <string_view>
#include <vector>
#include <sstream>
#include <optional>

namespace dll_forward_gen::sdk {

class PatternScan {
public:
    // Scans a specific memory buffer for an IDA-style signature (e.g. "48 89 5C 24 ? 48 83")
    static uint8_t* Scan(const uint8_t* base, size_t size, std::string_view pattern) {
        if (!base || size == 0 || pattern.empty()) {
            return nullptr;
        }

        const auto tokens = ParsePattern(pattern);
        if (tokens.empty() || tokens.size() > size) {
            return nullptr;
        }

        const size_t pattern_len = tokens.size();
        const size_t scan_limit = size - pattern_len;

        for (size_t i = 0; i <= scan_limit; ++i) {
            bool match = true;
            for (size_t j = 0; j < pattern_len; ++j) {
                const int16_t expected = tokens[j];
                if (expected != -1 && static_cast<uint8_t>(expected) != base[i + j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return const_cast<uint8_t*>(base + i);
            }
        }

        return nullptr;
    }

    // Scans the entire address space of a loaded module
    static uint8_t* ScanModule(const wchar_t* module_name, std::string_view pattern) {
        HMODULE hModule = GetModuleHandleW(module_name);
        if (!hModule) {
            return nullptr;
        }

        const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(hModule);
        if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }

        const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hModule) + dos_hdr->e_lfanew
        );
        if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }

        const size_t size_of_image = nt_hdrs->OptionalHeader.SizeOfImage;
        return Scan(reinterpret_cast<const uint8_t*>(hModule), size_of_image, pattern);
    }

    // Scans only a specific PE section within a loaded module (e.g. ".text")
    static uint8_t* ScanSection(const wchar_t* module_name, std::string_view section_name, std::string_view pattern) {
        HMODULE hModule = GetModuleHandleW(module_name);
        if (!hModule) {
            return nullptr;
        }

        const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(hModule);
        const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hModule) + dos_hdr->e_lfanew
        );

        const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(&nt_hdrs->OptionalHeader) + nt_hdrs->FileHeader.SizeOfOptionalHeader
        );

        for (WORD i = 0; i < nt_hdrs->FileHeader.NumberOfSections; ++i) {
            const auto& sec = sections[i];
            char sec_name_buf[9] = {0};
            std::memcpy(sec_name_buf, sec.Name, 8);

            if (section_name == sec_name_buf) {
                const uint8_t* sec_base = reinterpret_cast<const uint8_t*>(hModule) + sec.VirtualAddress;
                const size_t sec_size = sec.Misc.VirtualSize;
                return Scan(sec_base, sec_size, pattern);
            }
        }

        return nullptr;
    }

private:
    static std::vector<int16_t> ParsePattern(std::string_view pattern) {
        std::vector<int16_t> bytes;
        std::string token;
        std::stringstream ss(std::string{pattern});

        while (ss >> token) {
            if (token == "?" || token == "??") {
                bytes.push_back(-1); // Wildcard
            } else {
                try {
                    const auto val = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
                    bytes.push_back(val);
                } catch (...) {
                    // Invalid token, skip
                }
            }
        }

        return bytes;
    }
};

} // namespace dll_forward_gen::sdk
