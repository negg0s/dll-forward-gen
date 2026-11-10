// ===========================================================================
// tests/test_iat_resolver.cpp - Unit test for C++20 IATResolver SDK
// Part of dll-forward-gen
// ===========================================================================

#include "../sdk/iat_resolver.hpp"
#include <iostream>
#include <cassert>

int main() {
    std::cout << "[*] Testing C++20 IATResolver SDK...\n";

    HMODULE hSelf = GetModuleHandleW(nullptr);
    assert(hSelf != nullptr);

    // Self module imports KERNEL32.dll functions (e.g., GetModuleHandleW or ExitProcess)
    bool isBound = dll_forward_gen::loader::IATResolver::IsBound(
        reinterpret_cast<uint8_t*>(hSelf),
        "KERNEL32.dll",
        "GetModuleHandleW"
    );

    std::cout << "    [+] IAT IsBound check for KERNEL32.dll!GetModuleHandleW: " 
              << (isBound ? "TRUE (Bound)" : "FALSE") << "\n";

    // Null safety tests
    assert(!dll_forward_gen::loader::IATResolver::ResolveAll(nullptr));
    assert(!dll_forward_gen::loader::IATResolver::IsBound(nullptr, "KERNEL32.dll", "GetModuleHandleW"));
    assert(!dll_forward_gen::loader::IATResolver::IsBound(reinterpret_cast<uint8_t*>(hSelf), nullptr, nullptr));

    std::cout << "[+] test_iat_resolver completed successfully!\n";
    return 0;
}
