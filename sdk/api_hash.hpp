#pragma once

// ===========================================================================
// sdk/api_hash.hpp - Compile-Time & Runtime PE Export Hashing & Resolution SDK
// Part of dll-forward-gen (C++20 Header-Only Reverse Engineering SDK)
// Developed by @negg0s (Zero external dependencies)
// ===========================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <string_view>
#include <cstddef>

namespace dll_forward_gen::crypto {

enum class HashAlgorithm {
    ROR13,
    DJB2,
    FNV1a,
    CRC32
};

/**
 * @brief Zero-dependency C++20 compile-time (constexpr) and runtime hashing algorithms.
 */
class ApiHash {
public:
    /**
     * @brief 32-bit ROR13 hash commonly used in Windows shellcode and manual PE loaders.
     */
    static constexpr uint32_t ROR13(std::string_view str) noexcept {
        uint32_t h = 0;
        for (char c : str) {
            h = ((h >> 13) | (h << 19));
            h += static_cast<uint32_t>(static_cast<uint8_t>(c));
        }
        return h;
    }

    /**
     * @brief 32-bit DJB2 hash (Daniel J. Bernstein, 5381 multiplier).
     */
    static constexpr uint32_t DJB2(std::string_view str) noexcept {
        uint32_t h = 5381;
        for (char c : str) {
            h = ((h << 5) + h) + static_cast<uint32_t>(static_cast<uint8_t>(c));
        }
        return h;
    }

    /**
     * @brief 32-bit FNV-1a hash (Fowler-Noll-Vo).
     */
    static constexpr uint32_t FNV1a(std::string_view str) noexcept {
        uint32_t h = 0x811C9DC5;
        constexpr uint32_t prime = 0x01000193;
        for (char c : str) {
            h ^= static_cast<uint32_t>(static_cast<uint8_t>(c));
            h *= prime;
        }
        return h;
    }

    /**
     * @brief 32-bit CRC32 checksum (IEEE 802.3 polynomial 0xEDB88320).
     */
    static constexpr uint32_t CRC32(std::string_view str) noexcept {
        uint32_t crc = 0xFFFFFFFF;
        for (char c : str) {
            crc ^= static_cast<uint32_t>(static_cast<uint8_t>(c));
            for (int k = 0; k < 8; ++k) {
                crc = (crc >> 1) ^ (0xEDB88320 & (-(static_cast<int32_t>(crc & 1))));
            }
        }
        return ~crc;
    }

    /**
     * @brief Computes hash using specified HashAlgorithm enum.
     */
    static constexpr uint32_t Hash(std::string_view str, HashAlgorithm algo = HashAlgorithm::ROR13) noexcept {
        switch (algo) {
        case HashAlgorithm::ROR13: return ROR13(str);
        case HashAlgorithm::DJB2:  return DJB2(str);
        case HashAlgorithm::FNV1a: return FNV1a(str);
        case HashAlgorithm::CRC32: return CRC32(str);
        default: return 0;
        }
    }

    /**
     * @brief Resolves an exported function from a loaded module by its precomputed hash.
     * 
     * Traverses the in-memory PE Export Address Table (EAT) directly. Leaves zero plaintext
     * API string literals in the compiled binary when used with constexpr hashing.
     * 
     * @param hModule Base address of the loaded module.
     * @param targetHash Precomputed 32-bit hash.
     * @param algo Hash algorithm to use (default: ROR13).
     * @return FARPROC to the resolved function, or nullptr if not found.
     */
    static FARPROC GetProcAddressByHash(HMODULE hModule, uint32_t targetHash, HashAlgorithm algo = HashAlgorithm::ROR13) {
        if (!hModule) return nullptr;

        auto pBase = reinterpret_cast<const uint8_t*>(hModule);
        auto pDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        auto pNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        const IMAGE_DATA_DIRECTORY* pExpDirEntry = nullptr;
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            auto pNt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pNt);
            pExpDirEntry = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            auto pNt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(pNt);
            pExpDirEntry = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else {
            return nullptr;
        }

        if (!pExpDirEntry || pExpDirEntry->VirtualAddress == 0 || pExpDirEntry->Size == 0) {
            return nullptr;
        }

        auto pExpDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(pBase + pExpDirEntry->VirtualAddress);
        if (!pExpDir->NumberOfNames || !pExpDir->AddressOfNames) {
            return nullptr;
        }

        auto pNames = reinterpret_cast<const DWORD*>(pBase + pExpDir->AddressOfNames);
        auto pOrdinals = reinterpret_cast<const WORD*>(pBase + pExpDir->AddressOfNameOrdinals);
        auto pFunctions = reinterpret_cast<const DWORD*>(pBase + pExpDir->AddressOfFunctions);

        for (DWORD i = 0; i < pExpDir->NumberOfNames; ++i) {
            const char* funcName = reinterpret_cast<const char*>(pBase + pNames[i]);
            uint32_t h = Hash(funcName, algo);
            if (h == targetHash) {
                WORD ordinal = pOrdinals[i];
                DWORD funcRva = pFunctions[ordinal];

                // Check for forwarded export (RVA falls inside export directory)
                if (funcRva >= pExpDirEntry->VirtualAddress &&
                    funcRva < pExpDirEntry->VirtualAddress + pExpDirEntry->Size) {
                    // For forwarded exports, retrieve real address via LoadLibraryA/GetProcAddress
                    const char* fwdName = reinterpret_cast<const char*>(pBase + funcRva);
                    return ResolveForwarder(fwdName);
                }

                return reinterpret_cast<FARPROC>(const_cast<uint8_t*>(pBase + funcRva));
            }
        }

        return nullptr;
    }

private:
    static FARPROC ResolveForwarder(const char* forwardStr) {
        if (!forwardStr) return nullptr;
        // Format: "DLLNAME.FunctionName" or "DLLNAME.#123"
        const char* dot = nullptr;
        for (const char* p = forwardStr; *p; ++p) {
            if (*p == '.') {
                dot = p;
                break;
            }
        }
        if (!dot) return nullptr;

        char dllName[MAX_PATH] = {0};
        size_t dllLen = static_cast<size_t>(dot - forwardStr);
        if (dllLen >= MAX_PATH - 5) return nullptr;

        for (size_t i = 0; i < dllLen; ++i) dllName[i] = forwardStr[i];
        dllName[dllLen] = '.';
        dllName[dllLen + 1] = 'd';
        dllName[dllLen + 2] = 'l';
        dllName[dllLen + 3] = 'l';
        dllName[dllLen + 4] = '\0';

        HMODULE hTarget = LoadLibraryA(dllName);
        if (!hTarget) return nullptr;

        const char* funcTarget = dot + 1;
        if (*funcTarget == '#') {
            WORD ord = static_cast<WORD>(atoi(funcTarget + 1));
            return GetProcAddress(hTarget, MAKEINTRESOURCEA(ord));
        }

        return GetProcAddress(hTarget, funcTarget);
    }
};

} // namespace dll_forward_gen::crypto
