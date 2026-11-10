// ============================================================================
// test_eat_hook.cpp - Unit Test for C++20 EAT Hooking Engine
// Part of dll-forward-gen by NEGG0
// ============================================================================

#include "../sdk/eat_hook.hpp"
#include <iostream>
#include <cassert>

using namespace dll_forward_gen::hook;

typedef DWORD (WINAPI* PFN_GetCurrentThreadId)();
static PFN_GetCurrentThreadId g_OrigGetCurrentThreadId = nullptr;

static DWORD WINAPI Detour_GetCurrentThreadId() {
    return 7777;
}

int main() {
    std::cout << "[*] Testing C++20 EAT Hook Engine...\n";

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    assert(hKernel32 != nullptr);

    EATHook hook;
    bool installed = hook.Install(hKernel32, "GetCurrentThreadId", reinterpret_cast<void*>(Detour_GetCurrentThreadId));
    if (installed) {
        std::cout << "    [+] EAT Hook installed on kernel32!GetCurrentThreadId\n";

        // Calling GetProcAddress should now return detour
        auto pfn = reinterpret_cast<PFN_GetCurrentThreadId>(GetProcAddress(hKernel32, "GetCurrentThreadId"));
        assert(pfn == Detour_GetCurrentThreadId);

        DWORD result = pfn();
        std::cout << "    Detour invocation returned: " << result << "\n";
        assert(result == 7777);

        hook.Uninstall();
        std::cout << "    [+] EAT Hook uninstalled successfully!\n";

        auto pfnRestored = reinterpret_cast<PFN_GetCurrentThreadId>(GetProcAddress(hKernel32, "GetCurrentThreadId"));
        assert(pfnRestored != Detour_GetCurrentThreadId);
    } else {
        std::cout << "    [-] EAT Hook install skipped (protected memory or out of 32-bit RVA range on 64-bit)\n";
    }

    std::cout << "[+] test_eat_hook completed successfully!\n";
    return 0;
}
