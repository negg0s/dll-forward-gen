#pragma once
// ============================================================================
// eat_hook.hpp - Zero-Dependency Modern C++20 EAT (Export Address Table) Hook Engine
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Features:
//   - Intercepts dynamic resolution via GetProcAddress()
//   - Modifies AddressOfFunctions array in target module's export directory
//   - Support for both named and ordinal exports
//   - RAII ScopedEATHook for automatic restoration
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <string_view>
#include <utility>

namespace dll_forward_gen::hook {

class EATHook {
public:
    EATHook() noexcept = default;
    ~EATHook() {
        Uninstall();
    }

    EATHook(const EATHook&) = delete;
    EATHook& operator=(const EATHook&) = delete;

    EATHook(EATHook&& other) noexcept {
        MoveFrom(std::move(other));
    }

    EATHook& operator=(EATHook&& other) noexcept {
        if (this != &other) {
            Uninstall();
            MoveFrom(std::move(other));
        }
        return *this;
    }

    /// <summary>
    /// Hooks an exported function by name.
    /// Note: On x64, detour must be located within 2GB of hModule so that RVA fits in 32-bit DWORD.
    /// </summary>
    bool Install(HMODULE hModule, std::string_view procName, void* detour) noexcept {
        if (!hModule || !detour || procName.empty()) return false;
        return InstallInternal(hModule, procName, 0, detour);
    }

    /// <summary>
    /// Hooks an exported function by ordinal.
    /// </summary>
    bool InstallOrdinal(HMODULE hModule, uint16_t ordinal, void* detour) noexcept {
        if (!hModule || !detour || ordinal == 0) return false;
        return InstallInternal(hModule, {}, ordinal, detour);
    }

    void Uninstall() noexcept {
        if (is_installed_ && eat_entry_ && original_rva_ != 0) {
            DWORD old_protect = 0;
            if (VirtualProtect(eat_entry_, sizeof(DWORD), PAGE_READWRITE, &old_protect)) {
                *eat_entry_ = original_rva_;
                VirtualProtect(eat_entry_, sizeof(DWORD), old_protect, &old_protect);
            }
            is_installed_ = false;
            eat_entry_ = nullptr;
            original_rva_ = 0;
            original_func_ = nullptr;
        }
    }

    [[nodiscard]] bool IsInstalled() const noexcept { return is_installed_; }
    [[nodiscard]] void* GetOriginal() const noexcept { return original_func_; }

    template <typename Fn>
    [[nodiscard]] Fn GetOriginalAs() const noexcept {
        return reinterpret_cast<Fn>(original_func_);
    }

private:
    DWORD* eat_entry_ = nullptr;
    DWORD original_rva_ = 0;
    void* original_func_ = nullptr;
    bool is_installed_ = false;

    void MoveFrom(EATHook&& other) noexcept {
        eat_entry_ = other.eat_entry_;
        original_rva_ = other.original_rva_;
        original_func_ = other.original_func_;
        is_installed_ = other.is_installed_;

        other.eat_entry_ = nullptr;
        other.original_rva_ = 0;
        other.original_func_ = nullptr;
        other.is_installed_ = false;
    }

    bool InstallInternal(HMODULE hModule, std::string_view procName, uint16_t ordinal, void* detour) noexcept {
        Uninstall();

        auto* base = reinterpret_cast<uint8_t*>(hModule);
        const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos_hdr->e_lfanew);
        if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto& exp_dir_entry = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exp_dir_entry.VirtualAddress == 0 || exp_dir_entry.Size == 0) return false;

        auto* exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + exp_dir_entry.VirtualAddress);
        auto* func_table = reinterpret_cast<DWORD*>(base + exp_dir->AddressOfFunctions);
        auto* name_table = reinterpret_cast<DWORD*>(base + exp_dir->AddressOfNames);
        auto* ord_table = reinterpret_cast<WORD*>(base + exp_dir->AddressOfNameOrdinals);

        DWORD func_index = 0xFFFFFFFF;

        if (!procName.empty() && name_table && ord_table) {
            for (DWORD i = 0; i < exp_dir->NumberOfNames; ++i) {
                const char* cur_name = reinterpret_cast<const char*>(base + name_table[i]);
                if (procName == cur_name) {
                    func_index = ord_table[i];
                    break;
                }
            }
        } else if (ordinal != 0) {
            if (ordinal >= exp_dir->Base && ordinal < exp_dir->Base + exp_dir->NumberOfFunctions) {
                func_index = ordinal - exp_dir->Base;
            }
        }

        if (func_index == 0xFFFFFFFF || func_index >= exp_dir->NumberOfFunctions) {
            return false;
        }

        // Validate that detour RVA fits into DWORD
        const auto detour_addr = reinterpret_cast<uintptr_t>(detour);
        const auto base_addr = reinterpret_cast<uintptr_t>(base);
        const auto diff = detour_addr - base_addr;
        if (diff > 0xFFFFFFFFULL) {
            return false; // Out of 32-bit RVA range
        }

        DWORD* target_slot = &func_table[func_index];
        DWORD old_protect = 0;
        if (!VirtualProtect(target_slot, sizeof(DWORD), PAGE_READWRITE, &old_protect)) {
            return false;
        }

        original_rva_ = *target_slot;
        original_func_ = reinterpret_cast<void*>(base + original_rva_);
        *target_slot = static_cast<DWORD>(diff);

        VirtualProtect(target_slot, sizeof(DWORD), old_protect, &old_protect);

        eat_entry_ = target_slot;
        is_installed_ = true;
        return true;
    }
};

/// <summary>
/// RAII Scoped EAT Hook Helper
/// </summary>
class ScopedEATHook {
public:
    ScopedEATHook(HMODULE hModule, std::string_view procName, void* detour) {
        hook_.Install(hModule, procName, detour);
    }

    ~ScopedEATHook() {
        hook_.Uninstall();
    }

    ScopedEATHook(const ScopedEATHook&) = delete;
    ScopedEATHook& operator=(const ScopedEATHook&) = delete;

    [[nodiscard]] bool IsInstalled() const noexcept { return hook_.IsInstalled(); }
    [[nodiscard]] void* GetOriginal() const noexcept { return hook_.GetOriginal(); }

    template <typename Fn>
    [[nodiscard]] Fn GetOriginalAs() const noexcept {
        return hook_.GetOriginalAs<Fn>();
    }

private:
    EATHook hook_;
};

} // namespace dll_forward_gen::hook
