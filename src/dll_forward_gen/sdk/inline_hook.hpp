// ============================================================================
// inline_hook.hpp - Ultra-lightweight Zero-Dependency x64/x86 Inline Hooking SDK
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Clean C++20 header-only detour engine with trampoline generation and RAII.
// ============================================================================

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <memory>

namespace dll_forward_gen::sdk {

class InlineHook {
public:
#if defined(_M_X64) || defined(__x86_64__)
    static constexpr size_t kPatchSize = 14; // FF 25 00000000 [64-bit target]
#else
    static constexpr size_t kPatchSize = 5;  // E9 [32-bit relative offset]
#endif

    InlineHook() = default;

    ~InlineHook() {
        Remove();
    }

    InlineHook(const InlineHook&) = delete;
    InlineHook& operator=(const InlineHook&) = delete;

    InlineHook(InlineHook&& other) noexcept {
        MoveFrom(std::move(other));
    }

    InlineHook& operator=(InlineHook&& other) noexcept {
        if (this != &other) {
            Remove();
            MoveFrom(std::move(other));
        }
        return *this;
    }

    bool Install(void* target, void* detour, void** out_original_trampoline = nullptr) {
        if (!target || !detour || is_installed_) {
            return false;
        }

        target_addr_ = reinterpret_cast<uint8_t*>(target);
        detour_addr_ = reinterpret_cast<uint8_t*>(detour);

        // 1. Save original target bytes
        original_bytes_.resize(kPatchSize);
        std::memcpy(original_bytes_.data(), target_addr_, kPatchSize);

        // 2. Allocate executable memory for the trampoline
        trampoline_addr_ = reinterpret_cast<uint8_t*>(
            VirtualAlloc(nullptr, kPatchSize + kPatchSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        );
        if (!trampoline_addr_) {
            return false;
        }

        // Copy stolen original bytes into trampoline
        std::memcpy(trampoline_addr_, original_bytes_.data(), kPatchSize);

        // Append jump from trampoline back to target + kPatchSize
        WriteJump(trampoline_addr_ + kPatchSize, target_addr_ + kPatchSize);

        // 3. Patch the target function to jump to the detour
        DWORD old_protect = 0;
        if (!VirtualProtect(target_addr_, kPatchSize, PAGE_EXECUTE_READWRITE, &old_protect)) {
            VirtualFree(trampoline_addr_, 0, MEM_RELEASE);
            trampoline_addr_ = nullptr;
            return false;
        }

        WriteJump(target_addr_, detour_addr_);

        VirtualProtect(target_addr_, kPatchSize, old_protect, &old_protect);
        FlushInstructionCache(GetCurrentProcess(), target_addr_, kPatchSize);
        FlushInstructionCache(GetCurrentProcess(), trampoline_addr_, kPatchSize + kPatchSize);

        if (out_original_trampoline) {
            *out_original_trampoline = trampoline_addr_;
        }

        is_installed_ = true;
        return true;
    }

    bool Remove() {
        if (!is_installed_ || !target_addr_) {
            return false;
        }

        DWORD old_protect = 0;
        if (VirtualProtect(target_addr_, kPatchSize, PAGE_EXECUTE_READWRITE, &old_protect)) {
            std::memcpy(target_addr_, original_bytes_.data(), kPatchSize);
            VirtualProtect(target_addr_, kPatchSize, old_protect, &old_protect);
            FlushInstructionCache(GetCurrentProcess(), target_addr_, kPatchSize);
        }

        if (trampoline_addr_) {
            VirtualFree(trampoline_addr_, 0, MEM_RELEASE);
            trampoline_addr_ = nullptr;
        }

        is_installed_ = false;
        target_addr_ = nullptr;
        detour_addr_ = nullptr;
        return true;
    }

    [[nodiscard]] bool IsInstalled() const noexcept {
        return is_installed_;
    }

    [[nodiscard]] void* GetTrampoline() const noexcept {
        return trampoline_addr_;
    }

private:
    static void WriteJump(uint8_t* from, uint8_t* to) {
#if defined(_M_X64) || defined(__x86_64__)
        // 14-byte 64-bit absolute indirect jump: jmp [rip+0]
        from[0] = 0xFF;
        from[1] = 0x25;
        from[2] = 0x00;
        from[3] = 0x00;
        from[4] = 0x00;
        from[5] = 0x00;
        *reinterpret_cast<uint64_t*>(from + 6) = reinterpret_cast<uint64_t>(to);
#else
        // 5-byte 32-bit relative jump: jmp rel32
        from[0] = 0xE9;
        const int32_t relative_offset = static_cast<int32_t>(to - (from + 5));
        *reinterpret_cast<int32_t*>(from + 1) = relative_offset;
#endif
    }

    void MoveFrom(InlineHook&& other) noexcept {
        is_installed_ = other.is_installed_;
        target_addr_ = other.target_addr_;
        detour_addr_ = other.detour_addr_;
        trampoline_addr_ = other.trampoline_addr_;
        original_bytes_ = std::move(other.original_bytes_);

        other.is_installed_ = false;
        other.target_addr_ = nullptr;
        other.detour_addr_ = nullptr;
        other.trampoline_addr_ = nullptr;
    }

    bool is_installed_ = false;
    uint8_t* target_addr_ = nullptr;
    uint8_t* detour_addr_ = nullptr;
    uint8_t* trampoline_addr_ = nullptr;
    std::vector<uint8_t> original_bytes_;
};

// RAII Guard for auto-unhooking
class ScopedHook {
public:
    template <typename FnPtr, typename DetourPtr>
    ScopedHook(FnPtr target, DetourPtr detour, FnPtr* out_trampoline = nullptr) {
        hook_.Install(
            reinterpret_cast<void*>(target),
            reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(out_trampoline)
        );
    }

    ~ScopedHook() {
        hook_.Remove();
    }

    [[nodiscard]] bool IsActive() const noexcept {
        return hook_.IsInstalled();
    }

private:
    InlineHook hook_;
};

} // namespace dll_forward_gen::sdk
