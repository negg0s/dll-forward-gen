"""API Hashing utilities for PE exports and symbol identification.

Zero-dependency implementations of standard binary analysis and security algorithms:
- ROR13 (Standard shellcode / loader hash)
- DJB2 (Bernstein hash)
- FNV-1a (32-bit Fowler-Noll-Vo)
- CRC32 (Standard IEEE 802.3)
"""

import binascii
from typing import Dict


def ror13(name: str) -> int:
    """Compute 32-bit ROR13 hash commonly used in Windows shellcode and manual loaders."""
    h = 0
    for char in name:
        c = ord(char)
        h = ((h >> 13) | ((h << 19) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h + c) & 0xFFFFFFFF
    return h


def djb2(name: str) -> int:
    """Compute 32-bit DJB2 hash (Daniel J. Bernstein, 5381 base)."""
    h = 5381
    for char in name:
        h = (((h << 5) + h) + ord(char)) & 0xFFFFFFFF
    return h


def fnv1a(name: str) -> int:
    """Compute 32-bit FNV-1a hash (Fowler-Noll-Vo)."""
    h = 0x811C9DC5
    prime = 0x01000193
    for byte in name.encode("utf-8"):
        h = (h ^ byte) & 0xFFFFFFFF
        h = (h * prime) & 0xFFFFFFFF
    return h


def crc32_hash(name: str) -> int:
    """Compute standard 32-bit CRC32 checksum."""
    return binascii.crc32(name.encode("utf-8")) & 0xFFFFFFFF


def compute_all_hashes(name: str) -> Dict[str, str]:
    """Compute all supported hashes formatted as hex strings."""
    return {
        "ror13": f"0x{ror13(name):08X}",
        "djb2": f"0x{djb2(name):08X}",
        "fnv1a": f"0x{fnv1a(name):08X}",
        "crc32": f"0x{crc32_hash(name):08X}",
    }
