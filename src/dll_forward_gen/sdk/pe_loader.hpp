#pragma once
// ============================================================================
// pe_loader.hpp - Zero-Dependency Modern C++20 In-Memory PE Manual Mapper
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Features:
//   - Manually maps and executes PE binaries directly from a memory buffer
//   - Base relocation processing (DIR64 / HIGHLOW)
//   - Import Address Table (IAT) dependency resolution
//   - TLS Callbacks execution prior to entry point
//   - Full DllMain lifecycle invocation (DLL_PROCESS_ATTACH / DETACH)
//   - Zero telemetry, no LoadLibrary notification, undetectable by DLL hooks
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace dll_forward_gen::loader {

class MemoryPeLoader {
public:
    using DllMain_t = BOOL (APIENTRY*)(HMODULE, DWORD, LPVOID);

    /// <summary>
    /// Manually maps and initializes a PE DLL image directly from a memory buffer.
    /// Does not call LoadLibrary, evading DLL load notifications and registry hooks.
    /// </summary>
    static HMODULE LoadFromMemory(const void* peBuffer, size_t bufferSize) noexcept {
        if (!peBuffer || bufferSize < sizeof(IMAGE_DOS_HEADER)) return nullptr;

        const auto* raw = static_cast<const uint8_t*>(peBuffer);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > bufferSize) return nullptr;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(raw + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        // 1. Allocate virtual memory for the image
        const DWORD imageSize = nt->OptionalHeader.SizeOfImage;
        auto* imageBase = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        );
        if (!imageBase) return nullptr;

        // 2. Copy PE headers
        const DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
        std::memcpy(imageBase, raw, headerSize);

        // 3. Copy PE sections
        const auto* secHeader = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& sec = secHeader[i];
            if (sec.SizeOfRawData > 0 && sec.PointerToRawData > 0) {
                if (sec.PointerToRawData + sec.SizeOfRawData <= bufferSize &&
                    sec.VirtualAddress + sec.SizeOfRawData <= imageSize) {
                    std::memcpy(imageBase + sec.VirtualAddress, raw + sec.PointerToRawData, sec.SizeOfRawData);
                }
            }
        }

        // 4. Base Relocations
        const auto delta = reinterpret_cast<uintptr_t>(imageBase) - nt->OptionalHeader.ImageBase;
        if (delta != 0) {
            const auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir.VirtualAddress != 0 && relocDir.Size != 0) {
                auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(imageBase + relocDir.VirtualAddress);
                const auto* relocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(reloc) + relocDir.Size);

                while (reloc < relocEnd && reloc->SizeOfBlock > 0) {
                    const DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    const auto* entries = reinterpret_cast<const WORD*>(reloc + 1);
                    auto* pageBase = imageBase + reloc->VirtualAddress;

                    for (DWORD j = 0; j < count; ++j) {
                        const WORD type = entries[j] >> 12;
                        const WORD offset = entries[j] & 0x0FFF;

                        if (type == IMAGE_REL_BASED_DIR64) {
                            *reinterpret_cast<uint64_t*>(pageBase + offset) += delta;
                        } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                            *reinterpret_cast<uint32_t*>(pageBase + offset) += static_cast<uint32_t>(delta);
                        }
                    }
                    reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
                }
            }
        }

        // 5. Imports Resolution
        const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress != 0 && importDir.Size != 0) {
            auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(imageBase + importDir.VirtualAddress);
            for (; desc->Name != 0; ++desc) {
                const char* dllName = reinterpret_cast<const char*>(imageBase + desc->Name);
                HMODULE hDep = LoadLibraryA(dllName);
                if (!hDep) continue;

                auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(imageBase + desc->FirstThunk);
                auto* origThunk = desc->OriginalFirstThunk != 0
                    ? reinterpret_cast<IMAGE_THUNK_DATA*>(imageBase + desc->OriginalFirstThunk)
                    : thunk;

                for (; thunk->u1.Function != 0; ++thunk, ++origThunk) {
                    if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                        LPCSTR ord = MAKEINTRESOURCEA(IMAGE_ORDINAL(origThunk->u1.Ordinal));
                        thunk->u1.Function = reinterpret_cast<uintptr_t>(GetProcAddress(hDep, ord));
                    } else {
                        auto* nameData = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(imageBase + origThunk->u1.AddressOfData);
                        thunk->u1.Function = reinterpret_cast<uintptr_t>(GetProcAddress(hDep, nameData->Name));
                    }
                }
            }
        }

        // 6. Execute TLS Callbacks
        const auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress != 0 && tlsDir.Size != 0) {
            auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(imageBase + tlsDir.VirtualAddress);
            if (tls->AddressOfCallBacks != 0) {
                auto* callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
                while (*callbacks) {
                    (*callbacks)(reinterpret_cast<HMODULE>(imageBase), DLL_PROCESS_ATTACH, nullptr);
                    callbacks++;
                }
            }
        }

        // 7. Invoke DllMain if present
        if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
            auto pfnDllMain = reinterpret_cast<DllMain_t>(imageBase + nt->OptionalHeader.AddressOfEntryPoint);
            pfnDllMain(reinterpret_cast<HMODULE>(imageBase), DLL_PROCESS_ATTACH, nullptr);
        }

        return reinterpret_cast<HMODULE>(imageBase);
    }

    /// <summary>
    /// Resolves an exported symbol from a manually mapped PE module.
    /// </summary>
    static FARPROC GetProcAddressManual(HMODULE hManualModule, const char* procName) noexcept {
        if (!hManualModule || !procName) return nullptr;
        auto* base = reinterpret_cast<uint8_t*>(hManualModule);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        const auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress == 0 || expDir.Size == 0) return nullptr;

        auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + expDir.VirtualAddress);
        auto* functions = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);
        auto* names = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
        auto* ordinals = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(base + names[i]);
            if (std::strcmp(name, procName) == 0) {
                WORD fnIdx = ordinals[i];
                return reinterpret_cast<FARPROC>(base + functions[fnIdx]);
            }
        }
        return nullptr;
    }

    /// <summary>
    /// Unmaps and frees a manually mapped PE module.
    /// </summary>
    static void FreeManual(HMODULE hManualModule) noexcept {
        if (!hManualModule) return;
        auto* base = reinterpret_cast<uint8_t*>(hManualModule);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
            auto pfnDllMain = reinterpret_cast<DllMain_t>(base + nt->OptionalHeader.AddressOfEntryPoint);
            pfnDllMain(hManualModule, DLL_PROCESS_DETACH, nullptr);
        }

        VirtualFree(hManualModule, 0, MEM_RELEASE);
    }
};

} // namespace dll_forward_gen::loader
