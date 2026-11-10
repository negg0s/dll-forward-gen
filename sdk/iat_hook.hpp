#pragma once
// ============================================================================
// iat_hook.hpp - Zero-Dependency Modern C++20 IAT (Import Address Table) Hook Engine
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Features:
//   - Thread-safe atomic pointer replacement (InterlockedExchangePointer)
//   - Zero modification of .text section (evades code CRC/integrity checks)
//   - Support for both named and ordinal imports
//   - RAII ScopedIATHook for automatic cleanup
//   - Zero CRT/external dependencies, pure Win32 API
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <string_view>
#include <utility>

namespace dll_forward_gen::hook {

class IATHook {
public:
    IATHook() noexcept = default;
    ~IATHook() {
        Uninstall();
    }

    IATHook(const IATHook&) = delete;
    IATHook& operator=(const IATHook&) = delete;

    IATHook(IATHook&& other) noexcept {
        MoveFrom(std::move(other));
    }

    IATHook& operator=(IATHook&& other) noexcept {
        if (this != &other) {
            Uninstall();
            MoveFrom(std::move(other));
        }
        return *this;
    }

    /// <summary>
    /// Installs an IAT hook on the specified module.
    /// </summary>
    /// <param name="hModule">The module whose IAT is hooked (nullptr = current executable).</param>
    /// <param name="targetDll">Name of imported DLL (e.g. "kernel32.dll").</param>
    /// <param name="procName">Name of the imported function.</param>
    /// <param name="detour">Pointer to the replacement function.</param>
    /// <returns>True if successfully hooked, false otherwise.</returns>
    bool Install(HMODULE hModule, std::string_view targetDll, std::string_view procName, void* detour) noexcept {
        if (!detour) return false;
        return InstallInternal(hModule, targetDll, procName, 0, detour);
    }

    /// <summary>
    /// Installs an IAT hook for an ordinal import.
    /// </summary>
    bool InstallOrdinal(HMODULE hModule, std::string_view targetDll, uint16_t ordinal, void* detour) noexcept {
        if (!detour || ordinal == 0) return false;
        return InstallInternal(hModule, targetDll, {}, ordinal, detour);
    }

    /// <summary>
    /// Restores the original IAT entry.
    /// </summary>
    void Uninstall() noexcept {
        if (is_installed_ && iat_entry_ && original_func_) {
            DWORD old_protect = 0;
            if (VirtualProtect(iat_entry_, sizeof(void*), PAGE_READWRITE, &old_protect)) {
#if defined(_WIN64)
                InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(iat_entry_), original_func_);
#else
                InterlockedExchange(reinterpret_cast<LONG volatile*>(iat_entry_), reinterpret_cast<LONG>(original_func_));
#endif
                VirtualProtect(iat_entry_, sizeof(void*), old_protect, &old_protect);
            }
            is_installed_ = false;
            iat_entry_ = nullptr;
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
    void** iat_entry_ = nullptr;
    void* original_func_ = nullptr;
    bool is_installed_ = false;

    void MoveFrom(IATHook&& other) noexcept {
        iat_entry_ = other.iat_entry_;
        original_func_ = other.original_func_;
        is_installed_ = other.is_installed_;

        other.iat_entry_ = nullptr;
        other.original_func_ = nullptr;
        other.is_installed_ = false;
    }

    static bool CaseInsensitiveMatch(std::string_view a, const char* b) noexcept {
        if (!b) return false;
        size_t i = 0;
        for (; i < a.size() && b[i] != '\0'; ++i) {
            char ca = a[i];
            char cb = b[i];
            if (ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
            if (cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
            if (ca != cb) return false;
        }
        return i == a.size() && b[i] == '\0';
    }

    bool InstallInternal(HMODULE hModule, std::string_view targetDll, std::string_view procName, uint16_t ordinal, void* detour) noexcept {
        Uninstall();

        auto* base = reinterpret_cast<uint8_t*>(hModule ? hModule : GetModuleHandleW(nullptr));
        if (!base) return false;

        const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos_hdr->e_lfanew);
        if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto& import_dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) return false;

        auto* import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + import_dir.VirtualAddress);

        for (; import_desc->Name != 0; ++import_desc) {
            const char* dll_name = reinterpret_cast<const char*>(base + import_desc->Name);
            if (!CaseInsensitiveMatch(targetDll, dll_name)) {
                continue;
            }

            // OriginalFirstThunk = INT (Import Name Table)
            // FirstThunk = IAT (Import Address Table)
            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->FirstThunk);
            auto* orig_thunk = import_desc->OriginalFirstThunk != 0
                ? reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->OriginalFirstThunk)
                : thunk;

            for (; thunk->u1.Function != 0; ++thunk, ++orig_thunk) {
                bool match = false;

                if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
                    if (ordinal != 0 && (IMAGE_ORDINAL(orig_thunk->u1.Ordinal) == ordinal)) {
                        match = true;
                    }
                } else if (!procName.empty()) {
                    auto* import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + orig_thunk->u1.AddressOfData);
                    if (procName == import_by_name->Name) {
                        match = true;
                    }
                }

                if (match) {
                    void** slot = reinterpret_cast<void**>(&thunk->u1.Function);
                    DWORD old_protect = 0;
                    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old_protect)) {
                        return false;
                    }

                    original_func_ = *slot;
#if defined(_WIN64)
                    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(slot), detour);
#else
                    InterlockedExchange(reinterpret_cast<LONG volatile*>(slot), reinterpret_cast<LONG>(detour));
#endif
                    VirtualProtect(slot, sizeof(void*), old_protect, &old_protect);

                    iat_entry_ = slot;
                    is_installed_ = true;
                    return true;
                }
            }
        }

        return false;
    }
};

/// <summary>
/// RAII Scoped IAT Hook Helper
/// </summary>
class ScopedIATHook {
public:
    ScopedIATHook(HMODULE hModule, std::string_view targetDll, std::string_view procName, void* detour) {
        hook_.Install(hModule, targetDll, procName, detour);
    }

    ~ScopedIATHook() {
        hook_.Uninstall();
    }

    ScopedIATHook(const ScopedIATHook&) = delete;
    ScopedIATHook& operator=(const ScopedIATHook&) = delete;

    [[nodiscard]] bool IsInstalled() const noexcept { return hook_.IsInstalled(); }
    [[nodiscard]] void* GetOriginal() const noexcept { return hook_.GetOriginal(); }

    template <typename Fn>
    [[nodiscard]] Fn GetOriginalAs() const noexcept {
        return hook_.GetOriginalAs<Fn>();
    }

private:
    IATHook hook_;
};

} // namespace dll_forward_gen::hook
