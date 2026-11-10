import os
import unittest
from dll_forward_gen.pe_parser import PeParser, PeParseError
from dll_forward_gen.models import PeArch


class TestPeParser(unittest.TestCase):
    def test_invalid_magic_raises_error(self):
        data = b"NOT_A_PE_FILE_JUST_RANDOM_BYTES"
        with self.assertRaises(PeParseError):
            PeParser.parse_bytes(data)

    def test_truncated_dos_header_raises_error(self):
        data = b"MZ" + b"\x00" * 10
        with self.assertRaises(PeParseError):
            PeParser.parse_bytes(data)

    def test_parse_real_system_version_dll(self):
        version_dll = r"C:\Windows\System32\version.dll"
        if not os.path.exists(version_dll):
            self.skipTest(f"{version_dll} not found")

        parser = PeParser.from_file(version_dll)
        info = parser.parse()

        self.assertIn("version", info.dll_name.lower())
        self.assertIn(info.arch, [PeArch.X64, PeArch.X86, PeArch.ARM64])
        self.assertGreater(info.total_count, 0)

        # version.dll always exports GetFileVersionInfoW and VerQueryValueW
        names = {s.name for s in info.symbols if s.name}
        self.assertIn("GetFileVersionInfoW", names)
        self.assertIn("VerQueryValueW", names)

        # Check export symbol properties
        sym = next(s for s in info.symbols if s.name == "GetFileVersionInfoW")
        self.assertGreater(sym.ordinal, 0)
        self.assertGreater(sym.rva, 0)

    def test_rva_to_file_offset_logic(self):
        # Test helper method
        parser = PeParser(b"")
        parser.sections = [
            (0x1000, 0x1000, 0x400, 0x1000),  # va_start, virt_size, raw_ptr, raw_size
            (0x2000, 0x2000, 0x1400, 0x2000),
        ]
        # In section 0: RVA 0x1200 -> raw_ptr + (0x1200 - 0x1000) = 0x400 + 0x200 = 0x600
        offset = parser.rva_to_offset(0x1200)
        self.assertEqual(offset, 0x600)

        # In section 1: RVA 0x2500 -> 0x1400 + 0x500 = 0x1900
        offset2 = parser.rva_to_offset(0x2500)
        self.assertEqual(offset2, 0x1900)

        # Out of bounds RVA
        self.assertIsNone(parser.rva_to_offset(0x9999))


if __name__ == "__main__":
    unittest.main()
