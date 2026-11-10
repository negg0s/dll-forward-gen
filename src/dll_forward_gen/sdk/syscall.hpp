#pragma once

// ===========================================================================
// sdk/syscall.hpp - Dynamic Syscall Number (SSN) & Indirect Syscall Engine
// Part of dll-forward-gen (C++20 Header-Only Reverse Engineering SDK)
// Developed by @negg0s (Zero external dependencies)
// ===========================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <string_view>

namespace dll_forward_gen::syscall {

/**
 * @brief Dynamic Windows System Service Number (SSN) resolver & indirect syscall helper.
 * 
 * Implements Hell's Gate and Halo's Gate algorithms to recover true syscall numbers
 * even when ntdll.dll entrypoints are hooked by EDR or monitoring tools.
 */
class SyscallResolver {
public:
    /**
     * @brief Resolves the System Service Number (SSN) for an Nt* system call function in ntdll.dll.
     * 
     * Uses Hell's Gate with Halo's Gate neighbor scanning fallback if hooked.
     * @param functionName ASCII name of the Nt function (e.g. "NtAllocateVirtualMemory").
     * @return SSN integer >= 0 if found; -1 on failure.
     */
    static int32_t GetSyscallNumber(const char* functionName) {
        if (!functionName) return -1;

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return -1;

        auto pFunc = reinterpret_cast<const uint8_t*>(GetProcAddress(hNtdll, functionName));
        if (!pFunc) return -1;

        // 1. Hell's Gate: check if unhooked
        // 4C 8B D1          mov r10, rcx
        // B8 xx xx 00 00    mov eax, <SSN>
        if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
            return static_cast<int32_t>(*reinterpret_cast<const uint32_t*>(pFunc + 4));
        }

        // 2. Halo's Gate: scan neighboring stubs (+-32 byte intervals)
        constexpr size_t stubStride = 32;
        constexpr int maxDistance = 32;

        for (int i = 1; i <= maxDistance; ++i) {
            // Check downward neighbor
            const uint8_t* pDown = pFunc + (i * stubStride);
            if (pDown[0] == 0x4C && pDown[1] == 0x8B && pDown[2] == 0xD1 && pDown[3] == 0xB8) {
                uint32_t neighborSsn = *reinterpret_cast<const uint32_t*>(pDown + 4);
                return static_cast<int32_t>(neighborSsn - static_cast<uint32_t>(i));
            }

            // Check upward neighbor
            const uint8_t* pUp = pFunc - (i * stubStride);
            if (pUp[0] == 0x4C && pUp[1] == 0x8B && pUp[2] == 0xD1 && pUp[3] == 0xB8) {
                uint32_t neighborSsn = *reinterpret_cast<const uint32_t*>(pUp + 4);
                return static_cast<int32_t>(neighborSsn + static_cast<uint32_t>(i));
            }
        }

        return -1;
    }

    /**
     * @brief Finds the address of a genuine "syscall; ret" (0x0F 0x05 0xC3) gadget inside ntdll.dll.
     * 
     * Jumping to a gadget inside ntdll.dll ensures the kernel return RIP points
     * directly into ntdll.dll space, bypassing RIP stack integrity scanners.
     * @return Pointer to syscall instruction inside ntdll, or nullptr if not found.
     */
    static const void* GetSyscallGadget() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return nullptr;

        auto pBase = reinterpret_cast<const uint8_t*>(hNtdll);
        auto pDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        auto pNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        const auto* pSecHdr = IMAGE_FIRST_SECTION(pNt);
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i) {
            if (memcmp(pSecHdr[i].Name, ".text", 5) == 0) {
                const uint8_t* pText = pBase + pSecHdr[i].VirtualAddress;
                size_t textSize = pSecHdr[i].Misc.VirtualSize;

                for (size_t offset = 0; offset + 2 < textSize; ++offset) {
                    if (pText[offset] == 0x0F && pText[offset + 1] == 0x05 && pText[offset + 2] == 0xC3) {
                        return reinterpret_cast<const void*>(pText + offset);
                    }
                }
                break;
            }
        }

        return nullptr;
    }
};

} // namespace dll_forward_gen::syscall
