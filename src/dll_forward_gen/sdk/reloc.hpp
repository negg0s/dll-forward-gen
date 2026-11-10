#pragma once

// ===========================================================================
// sdk/reloc.hpp - In-Memory PE Base Relocation Processor
// Part of dll-forward-gen (C++20 Header-Only Reverse Engineering SDK)
// Developed by @negg0s (Zero external dependencies)
// ===========================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace dll_forward_gen::loader {

/**
 * @brief Processes and applies PE base relocations (.reloc) for manually mapped or rebased PE binaries.
 * 
 * Supports x64 (IMAGE_REL_BASED_DIR64) and x86 (IMAGE_REL_BASED_HIGHLOW, HIGH, LOW) relocations
 * with optional memory protection toggling via VirtualProtect.
 */
class RelocProcessor {
public:
    /**
     * @brief Applies relocations by calculating delta between the image's preferred ImageBase and actual pImageBase.
     * @param pImageBase Pointer to the mapped PE image in memory.
     * @param changeProtection If true, temporarily queries/adjusts VirtualProtect to ensure pages are writable.
     * @return true if relocations were applied successfully (or not needed); false on malformed PE or error.
     */
    static bool ApplyPreferred(uint8_t* pImageBase, bool changeProtection = false) {
        if (!pImageBase) return false;

        auto pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(pImageBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

        uintptr_t preferredBase = 0;
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            auto pNt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pNt);
            preferredBase = static_cast<uintptr_t>(pNt64->OptionalHeader.ImageBase);
        } else if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            auto pNt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pNt);
            preferredBase = static_cast<uintptr_t>(pNt32->OptionalHeader.ImageBase);
        } else {
            return false;
        }

        uintptr_t currentBase = reinterpret_cast<uintptr_t>(pImageBase);
        uintptr_t delta = currentBase - preferredBase;

        if (delta == 0) {
            return true; // Loaded at preferred base, no relocation needed
        }

        return ApplyRelocations(pImageBase, delta, changeProtection);
    }

    /**
     * @brief Applies base relocations with an explicit rebase delta offset.
     * @param pImageBase Pointer to the mapped PE image in memory.
     * @param delta Difference between new base and old base (newBase - oldBase).
     * @param changeProtection If true, invokes VirtualProtect to make target addresses writable.
     * @return true if all relocation blocks were successfully parsed and applied; false on error.
     */
    static bool ApplyRelocations(uint8_t* pImageBase, uintptr_t delta, bool changeProtection = false) {
        if (!pImageBase) return false;
        if (delta == 0) return true;

        auto pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(pImageBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

        PIMAGE_DATA_DIRECTORY pRelocDir = nullptr;
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            auto pNt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pNt);
            pRelocDir = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        } else if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            auto pNt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pNt);
            pRelocDir = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        } else {
            return false;
        }

        if (!pRelocDir || pRelocDir->VirtualAddress == 0 || pRelocDir->Size == 0) {
            return true; // Stripped or no relocations
        }

        auto pCurrentBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pImageBase + pRelocDir->VirtualAddress);
        const uint8_t* pRelocEnd = pImageBase + pRelocDir->VirtualAddress + pRelocDir->Size;

        while (reinterpret_cast<const uint8_t*>(pCurrentBlock) < pRelocEnd && pCurrentBlock->SizeOfBlock > 0) {
            if (pCurrentBlock->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
                return false; // Malformed block size
            }

            uint32_t entryCount = (pCurrentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            auto pEntries = reinterpret_cast<const uint16_t*>(reinterpret_cast<const uint8_t*>(pCurrentBlock) + sizeof(IMAGE_BASE_RELOCATION));

            for (uint32_t i = 0; i < entryCount; ++i) {
                uint16_t entry = pEntries[i];
                uint8_t type = static_cast<uint8_t>(entry >> 12);
                uint16_t offset = entry & 0x0FFF;

                uint8_t* pPatch = pImageBase + pCurrentBlock->VirtualAddress + offset;

                DWORD oldProtect = 0;
                if (changeProtection) {
                    VirtualProtect(pPatch, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
                }

                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // Padding entry, skip
                    break;

                case IMAGE_REL_BASED_HIGHLOW:
                    *reinterpret_cast<uint32_t*>(pPatch) += static_cast<uint32_t>(delta);
                    break;

                case IMAGE_REL_BASED_DIR64:
                    *reinterpret_cast<uint64_t*>(pPatch) += static_cast<uint64_t>(delta);
                    break;

                case IMAGE_REL_BASED_HIGH:
                    *reinterpret_cast<uint16_t*>(pPatch) += static_cast<uint16_t>((delta >> 16) & 0xFFFF);
                    break;

                case IMAGE_REL_BASED_LOW:
                    *reinterpret_cast<uint16_t*>(pPatch) += static_cast<uint16_t>(delta & 0xFFFF);
                    break;

                default:
                    // Unknown or unsupported relocation type
                    break;
                }

                if (changeProtection) {
                    VirtualProtect(pPatch, sizeof(uintptr_t), oldProtect, &oldProtect);
                }
            }

            pCurrentBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<uint8_t*>(pCurrentBlock) + pCurrentBlock->SizeOfBlock
            );
        }

        return true;
    }

    /**
     * @brief Counts the total number of non-absolute relocation entries in the PE image.
     */
    static size_t CountRelocations(const uint8_t* pImageBase) {
        if (!pImageBase) return 0;

        auto pDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pImageBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto pNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(pImageBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;

        const IMAGE_DATA_DIRECTORY* pRelocDir = nullptr;
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            auto pNt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pNt);
            pRelocDir = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        } else if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            auto pNt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(pNt);
            pRelocDir = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        } else {
            return 0;
        }

        if (!pRelocDir || pRelocDir->VirtualAddress == 0 || pRelocDir->Size == 0) {
            return 0;
        }

        size_t total = 0;
        auto pCurrentBlock = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(pImageBase + pRelocDir->VirtualAddress);
        const uint8_t* pRelocEnd = pImageBase + pRelocDir->VirtualAddress + pRelocDir->Size;

        while (reinterpret_cast<const uint8_t*>(pCurrentBlock) < pRelocEnd && pCurrentBlock->SizeOfBlock > 0) {
            if (pCurrentBlock->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

            uint32_t entryCount = (pCurrentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            auto pEntries = reinterpret_cast<const uint16_t*>(reinterpret_cast<const uint8_t*>(pCurrentBlock) + sizeof(IMAGE_BASE_RELOCATION));

            for (uint32_t i = 0; i < entryCount; ++i) {
                uint8_t type = static_cast<uint8_t>(pEntries[i] >> 12);
                if (type != IMAGE_REL_BASED_ABSOLUTE) {
                    ++total;
                }
            }

            pCurrentBlock = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<const uint8_t*>(pCurrentBlock) + pCurrentBlock->SizeOfBlock
            );
        }

        return total;
    }
};

} // namespace dll_forward_gen::loader
