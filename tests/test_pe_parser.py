import os
import unittest
from dll_forward_gen.pe_parser import PeParser, PeParseError, demangle_symbol, calculate_entropy
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
        self.assertTrue(len(info.sha256) == 64)

        # Mitigations check
        self.assertIsNotNone(info.mitigations)
        self.assertTrue(info.mitigations.dynamic_base)  # Windows system DLLs have ASLR
        self.assertTrue(info.mitigations.nx_compat)  # and DEP/NX

        # version.dll always exports GetFileVersionInfoW and VerQueryValueW
        names = {s.name for s in info.symbols if s.name}
        self.assertIn("GetFileVersionInfoW", names)
        self.assertIn("VerQueryValueW", names)

        sym = next(s for s in info.symbols if s.name == "GetFileVersionInfoW")
        self.assertGreater(sym.ordinal, 0)
        self.assertGreater(sym.rva, 0)

    def test_rva_to_file_offset_logic(self):
        parser = PeParser(b"")
        parser.sections = [
            (0x1000, 0x1000, 0x400, 0x1000),
            (0x2000, 0x2000, 0x1400, 0x2000),
        ]
        self.assertEqual(parser.rva_to_offset(0x1200), 0x600)
        self.assertEqual(parser.rva_to_offset(0x2500), 0x1900)
        self.assertIsNone(parser.rva_to_offset(0x9999))

    def test_demangle_msvc_symbol(self):
        mangled = "?MyFunction@@YAHXZ"
        demangled = demangle_symbol(mangled)
        if demangled is not None:
            self.assertIn("MyFunction", demangled)
        self.assertIsNone(demangle_symbol("PlainCFunction"))


    def test_entropy_calculation(self):
        # All zeros has 0 entropy
        self.assertEqual(calculate_entropy(b"\x00" * 256), 0.0)

        # Uniform distribution of all 256 bytes has maximum entropy of 8.0
        uniform = bytes(range(256)) * 4
        self.assertAlmostEqual(calculate_entropy(uniform), 8.0, places=3)

    def test_parse_sections_and_metrics(self):
        system_version = r"C:\Windows\System32\version.dll"
        if not os.path.exists(system_version):
            self.skipTest("version.dll not available in System32")

        parser = PeParser.from_file(system_version)
        info = parser.parse()

        self.assertGreater(len(info.sections), 0)
        sec_names = [s.name for s in info.sections]
        self.assertIn(".text", sec_names)

        text_sec = next(s for s in info.sections if s.name == ".text")
        self.assertGreater(text_sec.entropy, 4.0)
        self.assertLess(text_sec.entropy, 7.5)


    def test_parse_authenticode_signature(self):
        system_version = r"C:\Windows\System32\version.dll"
        if not os.path.exists(system_version):
            self.skipTest("version.dll not available in System32")

        parser = PeParser.from_file(system_version)
        info = parser.parse()

        self.assertIsNotNone(info.authenticode)
        self.assertTrue(info.authenticode.is_signed)
        self.assertGreater(info.authenticode.cert_size, 0)
        self.assertEqual(info.authenticode.cert_type, 0x0002)
        self.assertEqual(info.authenticode.revision, 0x0200)
        self.assertEqual(len(info.authenticode.authenticode_sha256), 64)


if __name__ == "__main__":
    unittest.main()
