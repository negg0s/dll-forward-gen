// ============================================================================
// test_lde.cpp - Unit Test for x86/x64 Length Disassembler Engine (LDE)
// Part of dll-forward-gen by NEGG0
// ============================================================================

#include "../sdk/lde.hpp"
#include <iostream>
#include <cassert>

using namespace dll_forward_gen::hook;

int main() {
    std::cout << "[*] Testing x86/x64 Length Disassembler Engine...\n";

    // 1. Single byte instructions
    const uint8_t nop[] = { 0x90 };
    assert(LengthDisassembler::DecodeInstruction(nop, true) == 1);
    assert(LengthDisassembler::DecodeInstruction(nop, false) == 1);

    const uint8_t ret[] = { 0xC3 };
    assert(LengthDisassembler::DecodeInstruction(ret, true) == 1);

    // 2. Multi-byte instructions
    // MOV [rsp+8], rbx: 48 89 5C 24 08 (5 bytes)
    const uint8_t mov_rsp[] = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
    assert(LengthDisassembler::DecodeInstruction(mov_rsp, true) == 5);

    // SUB rsp, 0x20: 48 83 EC 20 (4 bytes)
    const uint8_t sub_rsp[] = { 0x48, 0x83, 0xEC, 0x20 };
    assert(LengthDisassembler::DecodeInstruction(sub_rsp, true) == 4);

    // CALL rel32: E8 78 56 34 12 (5 bytes)
    const uint8_t call_rel[] = { 0xE8, 0x78, 0x56, 0x34, 0x12 };
    assert(LengthDisassembler::DecodeInstruction(call_rel, true) == 5);

    // MOV rax, imm64: 48 B8 88 77 66 55 44 33 22 11 (10 bytes)
    const uint8_t mov_imm64[] = { 0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
    assert(LengthDisassembler::DecodeInstruction(mov_imm64, true) == 10);

    // 3. Test GetDisplacedLength boundary protection
    // Stream:
    //   Inst 1: 5 bytes (MOV [rsp+8], rbx)
    //   Inst 2: 4 bytes (SUB rsp, 0x20)
    //   Inst 3: 5 bytes (CALL rel32)
    // Total = 14 bytes
    const uint8_t stream[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,       // 5 bytes
        0x48, 0x83, 0xEC, 0x20,             // 4 bytes
        0xE8, 0x78, 0x56, 0x34, 0x12,       // 5 bytes
        0x90, 0x90                          // NOPs
    };

    // Requesting 5 bytes returns 5
    assert(LengthDisassembler::GetDisplacedLength(stream, 5, true) == 5);
    // Requesting 6 bytes must return 9 (5 + 4), preventing splitting Inst 2!
    assert(LengthDisassembler::GetDisplacedLength(stream, 6, true) == 9);
    // Requesting 10 bytes must return 14 (5 + 4 + 5), preventing splitting Inst 3!
    assert(LengthDisassembler::GetDisplacedLength(stream, 10, true) == 14);
    // Requesting 14 bytes returns 14 exactly
    assert(LengthDisassembler::GetDisplacedLength(stream, 14, true) == 14);

    std::cout << "    [+] All instruction length tests and boundary checks PASSED!\n";
    std::cout << "[+] test_lde completed successfully!\n";
    return 0;
}
