#include "../sdk/pattern_scan.hpp"
#include <iostream>
#include <cassert>
#include <vector>

int main() {
    std::cout << "[TEST] Testing PatternScan...\n";

    // Synthetic memory buffer
    std::vector<uint8_t> memory = {
        0x90, 0x90, 0xCC, 0xCC,
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10,
        0x57, 0x48, 0x83, 0xEC, 0x20,
        0x90, 0x90
    };

    // Pattern with wildcards
    const char* pattern = "48 89 5C ? ? 48 89 ? ? 10 57";
    uint8_t* match = dll_forward_gen::sdk::PatternScan::Scan(
        memory.data(),
        memory.size(),
        pattern
    );

    assert(match != nullptr && "Pattern scan failed to find matching sequence!");
    assert(match == memory.data() + 4 && "Pattern match offset incorrect!");

    // Negative pattern test
    const char* non_existent = "FF FF FF FF ?? ?? DE AD BE EF";
    uint8_t* no_match = dll_forward_gen::sdk::PatternScan::Scan(
        memory.data(),
        memory.size(),
        non_existent
    );
    assert(no_match == nullptr && "Found unexpected match for non-existent pattern!");

    std::cout << "[SUCCESS] PatternScan passed all tests!\n";
    return 0;
}
