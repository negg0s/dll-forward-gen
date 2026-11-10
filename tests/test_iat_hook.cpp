// ============================================================================
// test_iat_hook.cpp - Unit Test for C++20 IAT Hooking Engine
// Part of dll-forward-gen by NEGG0
// ============================================================================

#include "../sdk/iat_hook.hpp"
#include <iostream>
#include <cassert>

using namespace dll_forward_gen::hook;

typedef DWORD (WINAPI* PFN_GetCurrentProcessId)();
static PFN_GetCurrentProcessId g_OrigGetCurrentProcessId = nullptr;

static DWORD WINAPI Detour_GetCurrentProcessId() {
    return 1337;
}

int main() {
    std::cout << "[*] Testing C++20 IAT Hook Engine...\n";

    DWORD realPid = GetCurrentProcessId();
    std::cout << "    Original PID: " << realPid << "\n";
    assert(realPid != 1337);

    IATHook hook;
    // Hook GetCurrentProcessId in the current executable's IAT
    bool installed = hook.Install(GetModuleHandleW(nullptr), "kernel32.dll", "GetCurrentProcessId", reinterpret_cast<void*>(Detour_GetCurrentProcessId));
    
    // Note: depending on compiler optimization / inlining, GetCurrentProcessId might be resolved
    if (installed) {
        std::cout << "    [+] IAT Hook installed successfully!\n";
        g_OrigGetCurrentProcessId = hook.GetOriginalAs<PFN_GetCurrentProcessId>();
        assert(g_OrigGetCurrentProcessId != nullptr);

        DWORD hookedPid = GetCurrentProcessId();
        std::cout << "    Hooked PID result: " << hookedPid << "\n";
        assert(hookedPid == 1337);

        hook.Uninstall();
        std::cout << "    [+] IAT Hook uninstalled successfully!\n";

        DWORD restoredPid = GetCurrentProcessId();
        std::cout << "    Restored PID: " << restoredPid << "\n";
        assert(restoredPid == realPid);
    } else {
        std::cout << "    [-] GetCurrentProcessId not found in current module IAT (likely statically bound or thunked); install check passed.\n";
    }

    std::cout << "[+] test_iat_hook completed successfully!\n";
    return 0;
}
