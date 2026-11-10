#include "../sdk/inline_hook.hpp"
#include <iostream>
#include <cassert>

// Disable inlining so function has a stable address and prologue
__declspec(noinline) int TargetFunction(int a, int b) {
    // Some dummy operations to ensure function is > 14 bytes
    volatile int res = a + b;
    res += a * 2;
    res -= b;
    return res;
}

using TargetFn_t = int (*)(int, int);
TargetFn_t g_pfn_Original = nullptr;

__declspec(noinline) int DetourFunction(int a, int b) {
    return 1337 + g_pfn_Original(a, b);
}

int main() {
    std::cout << "[TEST] Testing InlineHook...\n";

    const int initial_result = TargetFunction(10, 5);
    std::cout << "  Initial TargetFunction(10, 5) = " << initial_result << "\n";

    dll_forward_gen::sdk::InlineHook hook;
    bool ok = hook.Install(
        reinterpret_cast<void*>(&TargetFunction),
        reinterpret_cast<void*>(&DetourFunction),
        reinterpret_cast<void**>(&g_pfn_Original)
    );

    assert(ok && "Hook installation failed!");
    assert(hook.IsInstalled() && "Hook reported not installed!");

    const int hooked_result = TargetFunction(10, 5);
    std::cout << "  Hooked TargetFunction(10, 5) = " << hooked_result << "\n";
    assert(hooked_result == 1337 + initial_result && "Hook detour did not execute correctly!");

    // Test trampoline execution directly
    const int tramp_result = g_pfn_Original(10, 5);
    std::cout << "  Trampoline(10, 5) = " << tramp_result << "\n";
    assert(tramp_result == initial_result && "Trampoline did not return original value!");

    // Test unhooking
    hook.Remove();
    const int unhooked_result = TargetFunction(10, 5);
    std::cout << "  Unhooked TargetFunction(10, 5) = " << unhooked_result << "\n";
    assert(unhooked_result == initial_result && "Target function not restored after unhook!");

    std::cout << "[SUCCESS] InlineHook passed all tests!\n";
    return 0;
}
