#pragma once
// ============================================================================
// stealth.hpp - Zero-Dependency Anti-Analysis & Memory Cloaking SDK
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Features:
//   - UnlinkFromPEB: Removes loaded proxy DLL from PEB InLoadOrder, InMemoryOrder,
//     and InInitializationOrder linked lists (hides from EnumProcessModules).
//   - WipeHeaders: Zeroes in-memory DOS and NT headers to evade PE memory scanners.
//   - HideFromDebugger: Hides threads from debuggers via NtSetInformationThread (0x11).
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace dll_forward_gen::stealth {

typedef struct _PEB_LDR_DATA_EXT {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_EXT, *PPEB_LDR_DATA_EXT;

typedef struct _LDR_DATA_TABLE_ENTRY_EXT {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_EXT, *PLDR_DATA_TABLE_ENTRY_EXT;

/// <summary>
/// Retrieves the Process Environment Block (PEB) pointer directly from TEB.
/// </summary>
inline PPEB GetPeb() noexcept {
#if defined(_WIN64)
    return reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    return reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
}

/// <summary>
/// Unlinks the specified module from all PEB loader module lists.
/// Once unlinked, the module is invisible to CreateToolhelp32Snapshot and EnumProcessModules.
/// </summary>
/// <param name="hModule">Handle to the module to hide (nullptr = current executable).</param>
/// <returns>True if the module was found and unlinked, false otherwise.</returns>
inline bool UnlinkFromPEB(HMODULE hModule) noexcept {
    PPEB pPeb = GetPeb();
    if (!pPeb || !pPeb->Ldr) return false;

    auto* pLdr = reinterpret_cast<PPEB_LDR_DATA_EXT>(pPeb->Ldr);
    PLIST_ENTRY pHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pCurrent = pHead->Flink;

    void* targetBase = hModule ? static_cast<void*>(hModule) : static_cast<void*>(GetModuleHandleW(nullptr));

    while (pCurrent != pHead && pCurrent != nullptr) {
        auto* pEntry = CONTAINING_RECORD(pCurrent, LDR_DATA_TABLE_ENTRY_EXT, InLoadOrderLinks);

        if (pEntry->DllBase == targetBase) {
            // 1. Unlink InLoadOrderLinks
            pEntry->InLoadOrderLinks.Blink->Flink = pEntry->InLoadOrderLinks.Flink;
            pEntry->InLoadOrderLinks.Flink->Blink = pEntry->InLoadOrderLinks.Blink;

            // 2. Unlink InMemoryOrderLinks
            pEntry->InMemoryOrderLinks.Blink->Flink = pEntry->InMemoryOrderLinks.Flink;
            pEntry->InMemoryOrderLinks.Flink->Blink = pEntry->InMemoryOrderLinks.Blink;

            // 3. Unlink InInitializationOrderLinks
            if (pEntry->InInitializationOrderLinks.Flink != nullptr && pEntry->InInitializationOrderLinks.Blink != nullptr) {
                pEntry->InInitializationOrderLinks.Blink->Flink = pEntry->InInitializationOrderLinks.Flink;
                pEntry->InInitializationOrderLinks.Flink->Blink = pEntry->InInitializationOrderLinks.Blink;
            }

            // Clear entry contents to prevent forensic recovery from memory dumps
            pEntry->InLoadOrderLinks.Flink = pEntry->InLoadOrderLinks.Blink = nullptr;
            pEntry->InMemoryOrderLinks.Flink = pEntry->InMemoryOrderLinks.Blink = nullptr;
            pEntry->InInitializationOrderLinks.Flink = pEntry->InInitializationOrderLinks.Blink = nullptr;

            return true;
        }

        pCurrent = pCurrent->Flink;
    }

    return false;
}

/// <summary>
/// Erases the PE DOS and NT headers of the loaded module in memory.
/// Frustrates signature and memory dump tools that search for 'MZ' / 'PE'.
/// </summary>
inline bool WipeHeaders(HMODULE hModule) noexcept {
    if (!hModule) return false;

    auto* pBase = reinterpret_cast<uint8_t*>(hModule);
    const auto* pDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pBase);
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    const auto* pNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

    // Header size is defined by SizeOfHeaders in the optional header
    const DWORD headerSize = pNt->OptionalHeader.SizeOfHeaders;
    if (headerSize == 0 || headerSize > 0x10000) return false;

    DWORD oldProtect = 0;
    if (!VirtualProtect(pBase, headerSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    SecureZeroMemory(pBase, headerSize);

    // Restore to read-only or no-access to prevent re-execution of wiped header
    VirtualProtect(pBase, headerSize, oldProtect, &oldProtect);
    return true;
}

/// <summary>
/// Hides the target thread from debuggers via NtSetInformationThread (ThreadHideFromDebugger = 0x11).
/// Any attempt by a debugger to intercept events on this thread results in process termination.
/// </summary>
inline bool HideFromDebugger(HANDLE hThread = GetCurrentThread()) noexcept {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    using PFN_NtSetInformationThread = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    auto pfn = reinterpret_cast<PFN_NtSetInformationThread>(GetProcAddress(hNtdll, "NtSetInformationThread"));
    if (!pfn) return false;

    constexpr ULONG ThreadHideFromDebugger = 0x11;
    NTSTATUS status = pfn(hThread, ThreadHideFromDebugger, nullptr, 0);
    return (status >= 0);
}

} // namespace dll_forward_gen::stealth
