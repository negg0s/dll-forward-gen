#pragma once
// ============================================================================
// veh_hook.hpp - Stealth Hardware Breakpoint Hook Engine via Vectored Exception Handling
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Features:
//   - Zero code modification (DR0-DR3 hardware breakpoints)
//   - Undetectable by CRC32 / SHA256 code integrity scanners
//   - Automatic Resume Flag (RF) handling to prevent recursion
//   - RAII ScopedHardwareHook for clean thread context restoration
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <vector>
#include <functional>
#include <mutex>

namespace dll_forward_gen::hook {

class HardwareBreakpointHook {
public:
    static HardwareBreakpointHook& Instance() {
        static HardwareBreakpointHook instance;
        return instance;
    }

    bool Install(void* targetAddress, void* detourFunction, int drIndex = 0) {
        if (!targetAddress || !detourFunction || drIndex < 0 || drIndex > 3) return false;

        std::lock_guard<std::mutex> lock(mutex_);

        if (!veh_handle_) {
            veh_handle_ = AddVectoredExceptionHandler(1, VectoredHandler);
            if (!veh_handle_) return false;
        }

        target_address_ = targetAddress;
        detour_address_ = detourFunction;
        dr_index_ = drIndex;

        return SetHardwareBreakpointOnAllThreads(targetAddress, drIndex, true);
    }

    void Uninstall() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (target_address_ && dr_index_ >= 0) {
            SetHardwareBreakpointOnAllThreads(nullptr, dr_index_, false);
            target_address_ = nullptr;
            detour_address_ = nullptr;
            dr_index_ = -1;
        }

        if (veh_handle_) {
            RemoveVectoredExceptionHandler(veh_handle_);
            veh_handle_ = nullptr;
        }
    }

    [[nodiscard]] void* GetTarget() const noexcept { return target_address_; }
    [[nodiscard]] void* GetDetour() const noexcept { return detour_address_; }

private:
    HardwareBreakpointHook() = default;
    ~HardwareBreakpointHook() { Uninstall(); }

    PVOID veh_handle_ = nullptr;
    void* target_address_ = nullptr;
    void* detour_address_ = nullptr;
    int dr_index_ = -1;
    std::mutex mutex_;

    static LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
        if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
            auto& self = Instance();
            if (pExceptionInfo->ExceptionRecord->ExceptionAddress == self.target_address_) {
#if defined(_WIN64)
                pExceptionInfo->ContextRecord->Rip = reinterpret_cast<DWORD64>(self.detour_address_);
                pExceptionInfo->ContextRecord->EFlags |= 0x10000; // RF (Resume Flag)
#else
                pExceptionInfo->ContextRecord->Eip = reinterpret_cast<DWORD>(self.detour_address_);
                pExceptionInfo->ContextRecord->EFlags |= 0x10000; // RF (Resume Flag)
#endif
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    static bool SetHardwareBreakpointOnThread(HANDLE hThread, void* address, int drIndex, bool enable) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(hThread, &ctx)) return false;

        const uintptr_t addr = reinterpret_cast<uintptr_t>(address);

        if (enable) {
            switch (drIndex) {
                case 0: ctx.Dr0 = addr; break;
                case 1: ctx.Dr1 = addr; break;
                case 2: ctx.Dr2 = addr; break;
                case 3: ctx.Dr3 = addr; break;
            }
            // Enable local breakpoint (bits 0, 2, 4, 6)
            ctx.Dr7 |= (1ULL << (drIndex * 2));
            // Bits 16-31 control condition and size (00 = execute)
            ctx.Dr7 &= ~(0xFULL << (16 + drIndex * 4));
        } else {
            switch (drIndex) {
                case 0: ctx.Dr0 = 0; break;
                case 1: ctx.Dr1 = 0; break;
                case 2: ctx.Dr2 = 0; break;
                case 3: ctx.Dr3 = 0; break;
            }
            ctx.Dr7 &= ~(1ULL << (drIndex * 2));
        }

        return SetThreadContext(hThread, &ctx) != 0;
    }

    bool SetHardwareBreakpointOnAllThreads(void* address, int drIndex, bool enable) {
        const DWORD currentPid = GetCurrentProcessId();
        const DWORD currentTid = GetCurrentThreadId();

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);

        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == currentPid) {
                    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (hThread) {
                        if (te.th32ThreadID != currentTid) {
                            SuspendThread(hThread);
                        }

                        SetHardwareBreakpointOnThread(hThread, address, drIndex, enable);

                        if (te.th32ThreadID != currentTid) {
                            ResumeThread(hThread);
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(snapshot, &te));
        }

        CloseHandle(snapshot);
        return true;
    }
};

/// <summary>
/// RAII Scoped Hardware Breakpoint Hook
/// </summary>
class ScopedHardwareHook {
public:
    ScopedHardwareHook(void* target, void* detour, int drIndex = 0) {
        HardwareBreakpointHook::Instance().Install(target, detour, drIndex);
    }

    ~ScopedHardwareHook() {
        HardwareBreakpointHook::Instance().Uninstall();
    }

    ScopedHardwareHook(const ScopedHardwareHook&) = delete;
    ScopedHardwareHook& operator=(const ScopedHardwareHook&) = delete;
};

} // namespace dll_forward_gen::hook
