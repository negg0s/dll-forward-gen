#pragma once
// ============================================================================
// lde.hpp - Fast, Zero-Dependency x86/x64 Length Disassembler Engine (LDE)
// Part of dll-forward-gen by NEGG0 (https://github.com/negg0s/dll-forward-gen)
//
// Calculates exact instruction lengths (1-15 bytes) to guarantee that inline
// hooking trampolines never split instructions in half.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace dll_forward_gen::hook {

class LengthDisassembler {
public:
    /// <summary>
    /// Decodes the length of a single x86/x64 instruction at the specified address.
    /// </summary>
    /// <param name="code">Pointer to instruction bytes in memory.</param>
    /// <param name="is64">True for 64-bit mode (x64), false for 32-bit (x86).</param>
    /// <returns>Length of the instruction in bytes (1 to 15), or 0 on decode error.</returns>
    static size_t DecodeInstruction(const void* code, bool is64 = true) noexcept {
        if (!code) return 0;
        const auto* p = static_cast<const uint8_t*>(code);
        size_t offset = 0;

        bool op_override = false;
        bool addr_override = false;
        bool is_rex = false;
        bool rex_w = false;

        // 1. Parse legacy & REX prefixes
        while (offset < 15) {
            uint8_t b = p[offset];
            if (b == 0x66) {
                op_override = true;
                offset++;
            } else if (b == 0x67) {
                addr_override = true;
                offset++;
            } else if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                       b == 0x2E || b == 0x36 || b == 0x3E ||
                       b == 0x26 || b == 0x64 || b == 0x65) {
                offset++;
            } else if (is64 && (b >= 0x40 && b <= 0x4F)) {
                is_rex = true;
                if (b & 0x08) rex_w = true;
                offset++;
            } else {
                break;
            }
        }

        if (offset >= 15) return 0;

        // 2. Parse VEX prefix
        uint8_t b = p[offset++];
        if (b == 0xC5) {
            // 2-byte VEX
            if (offset >= 15) return 0;
            offset++; // VEX byte
            b = p[offset++]; // Opcode
        } else if (b == 0xC4) {
            // 3-byte VEX
            if (offset + 1 >= 15) return 0;
            offset += 2; // VEX bytes
            b = p[offset++]; // Opcode
        }

        // 3. Multi-byte opcodes (0x0F)
        bool has_modrm = false;
        size_t imm_size = 0;

        if (b == 0x0F) {
            if (offset >= 15) return 0;
            b = p[offset++];
            if (b == 0x38 || b == 0x3A) {
                // 3-byte escape
                uint8_t b2 = b;
                if (offset >= 15) return 0;
                b = p[offset++];
                has_modrm = true;
                if (b2 == 0x3A) imm_size = 1;
            } else {
                // 2-byte 0x0F escape
                if ((b >= 0x80 && b <= 0x8F)) {
                    // Jcc near (rel32)
                    imm_size = 4;
                } else if (b == 0xBA || (b >= 0x70 && b <= 0x73) || b == 0xA4 || b == 0xAC) {
                    has_modrm = true;
                    imm_size = 1;
                } else if ((b >= 0x20 && b <= 0x23) || (b >= 0x90 && b <= 0x9F) ||
                           (b >= 0xA0 && b <= 0xAF) || (b >= 0xB0 && b <= 0xB7) ||
                           (b >= 0xBC && b <= 0xBF) || (b >= 0xC0 && b <= 0xC6) ||
                           (b >= 0xD0 && b <= 0xD3) || (b >= 0xE0 && b <= 0xE3) ||
                           (b >= 0xF0 && b <= 0xF3)) {
                    has_modrm = true;
                }
            }
        } else {
            // 1-byte opcode table
            has_modrm = OpcodeHasModRM(b);
            imm_size = OpcodeImmediateSize(b, is64, op_override, rex_w);
        }

        // 4. ModR/M and SIB handling
        if (has_modrm) {
            if (offset >= 15) return 0;
            uint8_t modrm = p[offset++];
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t rm = modrm & 0x07;

            // Group opcodes with immediate bytes
            if (b == 0xF6) {
                if (((modrm >> 3) & 0x07) == 0) imm_size = 1;
            } else if (b == 0xF7) {
                if (((modrm >> 3) & 0x07) == 0) imm_size = (op_override ? 2 : 4);
            } else if (b == 0xC6) {
                imm_size = 1;
            } else if (b == 0xC7) {
                imm_size = (op_override ? 2 : 4);
            }

            if (mod != 3) { // Memory operand
                if (is64) {
                    if (rm == 4) { // SIB present
                        if (offset >= 15) return 0;
                        uint8_t sib = p[offset++];
                        uint8_t base = sib & 0x07;
                        if (mod == 0 && base == 5) offset += 4; // disp32
                    } else if (mod == 0 && rm == 5) {
                        offset += 4; // RIP + disp32
                    }
                } else {
                    if (rm == 4) { // 32-bit SIB
                        if (offset >= 15) return 0;
                        uint8_t sib = p[offset++];
                        uint8_t base = sib & 0x07;
                        if (mod == 0 && base == 5) offset += 4;
                    } else if (mod == 0 && rm == 5) {
                        offset += 4; // disp32
                    }
                }

                if (mod == 1) offset += 1; // disp8
                else if (mod == 2) offset += 4; // disp32
            }
        }

        offset += imm_size;
        return (offset <= 15) ? offset : 0;
    }

    /// <summary>
    /// Computes total number of whole instructions needed to satisfy minBytes.
    /// Guarantees that cutting the instruction stream at the returned size
    /// leaves no truncated instruction.
    /// </summary>
    static size_t GetDisplacedLength(const void* code, size_t minBytes, bool is64 = true) noexcept {
        if (!code || minBytes == 0) return 0;
        size_t total = 0;
        const auto* ptr = static_cast<const uint8_t*>(code);

        while (total < minBytes) {
            size_t len = DecodeInstruction(ptr + total, is64);
            if (len == 0) {
                // If decoding fails, fall back to minBytes directly
                return (total >= minBytes) ? total : minBytes;
            }
            total += len;
        }

        return total;
    }

private:
    static bool OpcodeHasModRM(uint8_t b) noexcept {
        // Opcode ranges that contain a ModR/M byte
        if ((b >= 0x00 && b <= 0x03) || (b >= 0x08 && b <= 0x0B) ||
            (b >= 0x10 && b <= 0x13) || (b >= 0x18 && b <= 0x1B) ||
            (b >= 0x20 && b <= 0x23) || (b >= 0x28 && b <= 0x2B) ||
            (b >= 0x30 && b <= 0x33) || (b >= 0x38 && b <= 0x3B) ||
            (b >= 0x80 && b <= 0x8F) || (b >= 0xC0 && b <= 0xC1) ||
            (b >= 0xC6 && b <= 0xC7) || (b >= 0xD0 && b <= 0xD3) ||
            (b >= 0xD8 && b <= 0xDF) || (b >= 0xF6 && b <= 0xF7) ||
            (b >= 0xFE && b <= 0xFF) || b == 0x69 || b == 0x6B ||
            b == 0x84 || b == 0x85 || b == 0x86 || b == 0x87 ||
            b == 0x88 || b == 0x89 || b == 0x8A || b == 0x8B ||
            b == 0x8D) {
            return true;
        }
        return false;
    }

    static size_t OpcodeImmediateSize(uint8_t b, bool is64, bool op_override, bool rex_w) noexcept {
        (void)is64;
        // Immediate byte count lookup
        if (b == 0x04 || b == 0x0C || b == 0x14 || b == 0x1C ||
            b == 0x24 || b == 0x2C || b == 0x34 || b == 0x3C ||
            (b >= 0x70 && b <= 0x7F) || (b >= 0xB0 && b <= 0xB7) ||
            b == 0xCD || b == 0xE4 || b == 0xE5 || b == 0xE6 ||
            b == 0xE7 || b == 0xEB || b == 0x6A || b == 0x80 ||
            b == 0x82 || b == 0x83 || b == 0xC0 || b == 0xC1 ||
            b == 0xC6 || b == 0x6B) {
            return 1;
        }

        if (b == 0xC2 || b == 0xCA) {
            return 2;
        }

        if (b == 0x05 || b == 0x0D || b == 0x15 || b == 0x1D ||
            b == 0x25 || b == 0x2D || b == 0x35 || b == 0x3D ||
            b == 0x68 || b == 0x69 || b == 0x81 || b == 0xC7 ||
            b == 0xE8 || b == 0xE9) {
            return op_override ? 2 : 4;
        }

        if (b >= 0xB8 && b <= 0xBF) {
            // MOV reg, imm32 / imm64
            if (rex_w) return 8;
            return op_override ? 2 : 4;
        }

        return 0;
    }
};

} // namespace dll_forward_gen::hook
