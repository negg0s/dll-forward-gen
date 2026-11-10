// ===========================================================================
// tests/test_reloc.cpp - Unit test for C++20 RelocProcessor SDK
// Part of dll-forward-gen
// ===========================================================================

#include "../sdk/reloc.hpp"
#include <iostream>
#include <vector>
#include <cassert>

int main() {
    std::cout << "[*] Testing C++20 RelocProcessor SDK...\n";

    // 1. Null safety checks
    assert(!dll_forward_gen::loader::RelocProcessor::ApplyRelocations(nullptr, 0x1000));
    assert(!dll_forward_gen::loader::RelocProcessor::ApplyPreferred(nullptr));
    assert(dll_forward_gen::loader::RelocProcessor::CountRelocations(nullptr) == 0);

    // 2. Delta 0 returns true immediately
    uint8_t dummyByte = 0;
    assert(dll_forward_gen::loader::RelocProcessor::ApplyRelocations(&dummyByte, 0));

    // 3. Inspect loaded system DLL relocations
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        size_t ntdllRelocs = dll_forward_gen::loader::RelocProcessor::CountRelocations(
            reinterpret_cast<const uint8_t*>(hNtdll)
        );
        std::cout << "    [+] CountRelocations(ntdll.dll): " << ntdllRelocs << " entries\n";
    }

    // 4. Construct a synthetic PE in memory to test real relocation math
    // Layout:
    // [0x00..0x3F] DOS Header (e_magic = 'MZ', e_lfanew = 0x40)
    // [0x40..0x17F] NT Headers 64
    // [0x200..0x2FF] Relocation Directory Block
    // [0x300..0x3FF] Target memory region with pointers to patch

    std::vector<uint8_t> peBuffer(0x1000, 0);
    uint8_t* pBuf = peBuffer.data();

    auto pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pBuf);
    pDos->e_magic = IMAGE_DOS_SIGNATURE;
    pDos->e_lfanew = 0x40;

    auto pNt = reinterpret_cast<PIMAGE_NT_HEADERS64>(pBuf + 0x40);
    pNt->Signature = IMAGE_NT_SIGNATURE;
    pNt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    pNt->OptionalHeader.ImageBase = 0x140000000ULL;

    const DWORD relocRva = 0x200;
    const DWORD targetRva = 0x300;

    // Target values to patch
    uint64_t* pTarget64 = reinterpret_cast<uint64_t*>(pBuf + targetRva);
    *pTarget64 = 0x140001000ULL;

    uint32_t* pTarget32 = reinterpret_cast<uint32_t*>(pBuf + targetRva + 8);
    *pTarget32 = 0x00002000;

    // Relocation block setup
    // Block VirtualAddress = 0x300
    // Entry 0: DIR64 at offset 0 (targets pTarget64)
    // Entry 1: HIGHLOW at offset 8 (targets pTarget32)
    // Entry 2: ABSOLUTE padding at offset 0
    auto pRelocDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pRelocDir->VirtualAddress = relocRva;
    pRelocDir->Size = sizeof(IMAGE_BASE_RELOCATION) + 3 * sizeof(uint16_t);

    auto pBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBuf + relocRva);
    pBlock->VirtualAddress = targetRva;
    pBlock->SizeOfBlock = static_cast<DWORD>(pRelocDir->Size);

    auto pEntries = reinterpret_cast<uint16_t*>(pBuf + relocRva + sizeof(IMAGE_BASE_RELOCATION));
    pEntries[0] = static_cast<uint16_t>((IMAGE_REL_BASED_DIR64 << 12) | 0x000); // offset 0
    pEntries[1] = static_cast<uint16_t>((IMAGE_REL_BASED_HIGHLOW << 12) | 0x008); // offset 8
    pEntries[2] = static_cast<uint16_t>((IMAGE_REL_BASED_ABSOLUTE << 12) | 0x000); // padding

    // Verify CountRelocations skips ABSOLUTE
    size_t count = dll_forward_gen::loader::RelocProcessor::CountRelocations(pBuf);
    assert(count == 2);
    std::cout << "    [+] CountRelocations(mock_pe) = " << count << " (expected 2)\n";

    // Apply relocations with delta = 0x10000
    const uintptr_t testDelta = 0x10000;
    bool success = dll_forward_gen::loader::RelocProcessor::ApplyRelocations(pBuf, testDelta, false);
    assert(success);

    // Verify DIR64 patched: 0x140001000 + 0x10000 = 0x140011000
    assert(*pTarget64 == 0x140011000ULL);
    std::cout << "    [+] DIR64 patched value: 0x" << std::hex << *pTarget64 << std::dec << " (expected 0x140011000)\n";

    // Verify HIGHLOW patched: 0x2000 + 0x10000 = 0x12000
    assert(*pTarget32 == 0x00012000);
    std::cout << "    [+] HIGHLOW patched value: 0x" << std::hex << *pTarget32 << std::dec << " (expected 0x12000)\n";

    std::cout << "[+] test_reloc completed successfully!\n";
    return 0;
}
