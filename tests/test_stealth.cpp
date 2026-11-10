// ============================================================================
// test_stealth.cpp - Unit Test for C++20 Anti-Analysis & Memory Cloaking SDK
// Part of dll-forward-gen by NEGG0
// ============================================================================

#include "../sdk/stealth.hpp"
#include <iostream>
#include <cassert>

using namespace dll_forward_gen::stealth;

int main() {
    std::cout << "[*] Testing C++20 Stealth SDK...\n";

    // 1. Test GetPeb
    PPEB pPeb = GetPeb();
    assert(pPeb != nullptr);
    assert(pPeb->ImageBaseAddress != nullptr);
    std::cout << "    [+] GetPeb verified: ImageBase = " << pPeb->ImageBaseAddress << "\n";

    // 2. Test HideFromDebugger
    bool hideSuccess = HideFromDebugger(GetCurrentThread());
    std::cout << "    [+] HideFromDebugger executed: result = " << (hideSuccess ? "TRUE" : "FALSE") << "\n";

    // 3. Test UnlinkFromPEB on dynamically loaded module
    HMODULE hTestMod = LoadLibraryW(L"version.dll");
    if (hTestMod) {
        std::cout << "    [+] Loaded version.dll at " << hTestMod << "\n";
        bool unlinked = UnlinkFromPEB(hTestMod);
        std::cout << "    [+] UnlinkFromPEB result: " << (unlinked ? "TRUE" : "FALSE") << "\n";
        assert(unlinked == true);
    }

    std::cout << "[+] test_stealth completed successfully!\n";
    return 0;
}
