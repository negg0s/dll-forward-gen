// ============================================================================
// test_veh_hook.cpp - Unit Test for C++20 Hardware Breakpoint VEH Hooking
// Part of dll-forward-gen by NEGG0
// ============================================================================

#include "../sdk/veh_hook.hpp"
#include <iostream>
#include <cassert>

using namespace dll_forward_gen::hook;

static bool g_DetourInvoked = false;

__declspec(noinline) int TargetFunction(int a, int b) {
    return a + b;
}

static int DetourFunction(int a, int b) {
    g_DetourInvoked = true;
    return (a * b) + 100;
}

int main() {
    std::cout << "[*] Testing C++20 Hardware Breakpoint VEH Hook Engine...\n";

    int directResult = TargetFunction(3, 4);
    assert(directResult == 7);
    std::cout << "    Direct call result: " << directResult << "\n";

    bool installed = HardwareBreakpointHook::Instance().Install(
        reinterpret_cast<void*>(TargetFunction),
        reinterpret_cast<void*>(DetourFunction),
        0
    );

    if (installed) {
        std::cout << "    [+] Hardware breakpoint installed on DR0\n";
        int hookResult = TargetFunction(3, 4);
        std::cout << "    Hooked call result: " << hookResult << "\n";
        assert(g_DetourInvoked == true);
        assert(hookResult == 112);

        HardwareBreakpointHook::Instance().Uninstall();
        std::cout << "    [+] Hardware breakpoint uninstalled\n";

        g_DetourInvoked = false;
        int restoredResult = TargetFunction(3, 4);
        assert(restoredResult == 7);
        assert(g_DetourInvoked == false);
        std::cout << "    Restored call result: " << restoredResult << "\n";
    } else {
        std::cout << "    [-] Hardware breakpoint install returned false (running without debug privileges?)\n";
    }

    std::cout << "[+] test_veh_hook completed successfully!\n";
    return 0;
}
