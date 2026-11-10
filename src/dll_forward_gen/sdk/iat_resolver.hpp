#pragma once

// ===========================================================================
// sdk/iat_resolver.hpp - In-Memory PE Import Address Table (IAT) Resolver
// Part of dll-forward-gen (C++20 Header-Only Reverse Engineering SDK)
// Developed by @negg0s (Zero external dependencies)
// ===========================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace dll_forward_gen::loader {

/**
 * @brief Resolves and binds all imported DLLs and function pointers in an in-memory mapped PE image.
 * 
 * Essential for manual PE mapping, unpacking, stealth DLL loading, and recovering damaged IATs.
 */
class IATResolver {
public:
    /**
     * @brief Resolves all import descriptors in a mapped PE image using LoadLibraryA and GetProcAddress.
     * @param pImageBase Pointer to the mapped PE image base.
     * @return true if all imports were successfully resolved and bound; false otherwise.
     */
    static bool ResolveAll(uint8_t* pImageBase) {
        if (!pImageBase) return false;

        auto pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(pImageBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

        PIMAGE_DATA_DIRECTORY pImportDir = nullptr;
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            auto pNt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pNt);
            pImportDir = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        } else if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            auto pNt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pNt);
            pImportDir = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        } else {
            return false;
        }

        if (!pImportDir || pImportDir->VirtualAddress == 0 || pImportDir->Size == 0) {
            return true; // No imports required
        }

        auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pImageBase + pImportDir->VirtualAddress);

        for (; pImportDesc->Name != 0; ++pImportDesc) {
            const char* dllName = reinterpret_cast<const char*>(pImageBase + pImportDesc->Name);
            HMODULE hDll = LoadLibraryA(dllName);
            if (!hDll) return false;

            uintptr_t thunkRva = pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk;
            uint8_t* pThunk = pImageBase + thunkRva;
            uint8_t* pIat = pImageBase + pImportDesc->FirstThunk;

            bool is64 = (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

            while (true) {
                if (is64) {
                    auto pOrigThunk64 = reinterpret_cast<PIMAGE_THUNK_DATA64>(pThunk);
                    auto pIat64 = reinterpret_cast<PIMAGE_THUNK_DATA64>(pIat);
                    if (pOrigThunk64->u1.AddressOfData == 0) break;

                    FARPROC pfn = nullptr;
                    if (IMAGE_SNAP_BY_ORDINAL64(pOrigThunk64->u1.Ordinal)) {
                        WORD ord = IMAGE_ORDINAL64(pOrigThunk64->u1.Ordinal);
                        pfn = GetProcAddress(hDll, MAKEINTRESOURCEA(ord));
                    } else {
                        auto pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pImageBase + pOrigThunk64->u1.AddressOfData);
                        pfn = GetProcAddress(hDll, pImportByName->Name);
                    }

                    if (!pfn) return false;
                    pIat64->u1.Function = reinterpret_cast<ULONGLONG>(pfn);
                    pThunk += sizeof(IMAGE_THUNK_DATA64);
                    pIat += sizeof(IMAGE_THUNK_DATA64);
                } else {
                    auto pOrigThunk32 = reinterpret_cast<PIMAGE_THUNK_DATA32>(pThunk);
                    auto pIat32 = reinterpret_cast<PIMAGE_THUNK_DATA32>(pIat);
                    if (pOrigThunk32->u1.AddressOfData == 0) break;

                    FARPROC pfn = nullptr;
                    if (IMAGE_SNAP_BY_ORDINAL32(pOrigThunk32->u1.Ordinal)) {
                        WORD ord = IMAGE_ORDINAL32(pOrigThunk32->u1.Ordinal);
                        pfn = GetProcAddress(hDll, MAKEINTRESOURCEA(ord));
                    } else {
                        auto pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pImageBase + pOrigThunk32->u1.AddressOfData);
                        pfn = GetProcAddress(hDll, pImportByName->Name);
                    }

                    if (!pfn) return false;
                    pIat32->u1.Function = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pfn));
                    pThunk += sizeof(IMAGE_THUNK_DATA32);
                    pIat += sizeof(IMAGE_THUNK_DATA32);
                }
            }
        }
        return true;
    }

    /**
     * @brief Checks if a specific function's IAT entry in a module has been bound to a live pointer.
     */
    static bool IsBound(uint8_t* pImageBase, const char* dllName, const char* funcName) {
        if (!pImageBase || !dllName || !funcName) return false;

        auto pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(pImageBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

        PIMAGE_DATA_DIRECTORY pImportDir = nullptr;
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            auto pNt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pNt);
            pImportDir = &pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        } else {
            auto pNt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pNt);
            pImportDir = &pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }

        if (!pImportDir || pImportDir->VirtualAddress == 0) return false;

        auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pImageBase + pImportDir->VirtualAddress);

        for (; pImportDesc->Name != 0; ++pImportDesc) {
            const char* curDllName = reinterpret_cast<const char*>(pImageBase + pImportDesc->Name);
            if (_stricmp(curDllName, dllName) == 0) {
                uintptr_t thunkRva = pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk;
                uint8_t* pThunk = pImageBase + thunkRva;
                uint8_t* pIat = pImageBase + pImportDesc->FirstThunk;
                bool is64 = (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

                while (true) {
                    if (is64) {
                        auto pOrig64 = reinterpret_cast<PIMAGE_THUNK_DATA64>(pThunk);
                        auto pIat64 = reinterpret_cast<PIMAGE_THUNK_DATA64>(pIat);
                        if (pOrig64->u1.AddressOfData == 0) break;
                        if (!IMAGE_SNAP_BY_ORDINAL64(pOrig64->u1.Ordinal)) {
                            auto pName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pImageBase + pOrig64->u1.AddressOfData);
                            if (strcmp(pName->Name, funcName) == 0) {
                                return pIat64->u1.Function != 0 && pIat64->u1.Function != pOrig64->u1.AddressOfData;
                            }
                        }
                        pThunk += sizeof(IMAGE_THUNK_DATA64);
                        pIat += sizeof(IMAGE_THUNK_DATA64);
                    } else {
                        auto pOrig32 = reinterpret_cast<PIMAGE_THUNK_DATA32>(pThunk);
                        auto pIat32 = reinterpret_cast<PIMAGE_THUNK_DATA32>(pIat);
                        if (pOrig32->u1.AddressOfData == 0) break;
                        if (!IMAGE_SNAP_BY_ORDINAL32(pOrig32->u1.Ordinal)) {
                            auto pName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pImageBase + pOrig32->u1.AddressOfData);
                            if (strcmp(pName->Name, funcName) == 0) {
                                return pIat32->u1.Function != 0 && pIat32->u1.Function != pOrig32->u1.AddressOfData;
                            }
                        }
                        pThunk += sizeof(IMAGE_THUNK_DATA32);
                        pIat += sizeof(IMAGE_THUNK_DATA32);
                    }
                }
            }
        }
        return false;
    }
};

} // namespace dll_forward_gen::loader
