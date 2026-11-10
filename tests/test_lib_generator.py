import unittest
from pathlib import Path
import tempfile
import struct

from dll_forward_gen.models import ExportSymbol, PeArch, PeExportInfo
from dll_forward_gen.lib_generator import ImportLibGenerator, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARM64


class TestLibGenerator(unittest.TestCase):
    def setUp(self):
        self.symbols = [
            ExportSymbol(ordinal=1, rva=0x1000, name="DirectFunctionA"),
            ExportSymbol(ordinal=2, rva=0x1100, name="DirectFunctionB"),
            ExportSymbol(ordinal=3, rva=0x1200, name=None),  # Ordinal-only
        ]
        self.info_x64 = PeExportInfo(
            filepath=r"C:\Windows\System32\mytest.dll",
            dll_name="mytest.dll",
            arch=PeArch.X64,
            timestamp=12345678,
            ordinal_base=1,
            symbols=self.symbols,
        )
        self.info_x86 = PeExportInfo(
            filepath=r"C:\Windows\SysWOW64\mytest.dll",
            dll_name="mytest.dll",
            arch=PeArch.X86,
            timestamp=12345678,
            ordinal_base=1,
            symbols=self.symbols,
        )
        self.info_arm64 = PeExportInfo(
            filepath=r"C:\Windows\System32\mytest.dll",
            dll_name="mytest.dll",
            arch=PeArch.ARM64,
            timestamp=12345678,
            ordinal_base=1,
            symbols=self.symbols,
        )

    def test_generate_x64_import_lib(self):
        gen = ImportLibGenerator(self.info_x64)
        lib_bytes = gen.build_library_bytes()

        # 1. Validate AR archive magic
        self.assertTrue(lib_bytes.startswith(b"!<arch>\n"))

        # 2. Validate First Linker Member
        self.assertIn(b"/               ", lib_bytes[:100])

        # 3. Validate presence of symbols and __imp_ aliases in string table
        self.assertIn(b"DirectFunctionA\x00", lib_bytes)
        self.assertIn(b"__imp_DirectFunctionA\x00", lib_bytes)
        self.assertIn(b"DirectFunctionB\x00", lib_bytes)
        self.assertIn(b"__imp_DirectFunctionB\x00", lib_bytes)
        self.assertIn(b"Ordinal_3\x00", lib_bytes)
        self.assertIn(b"__imp_Ordinal_3\x00", lib_bytes)

        # 4. Check Short Import Header signature (0x0000, 0xFFFF) and machine type (AMD64 = 0x8664)
        short_hdr_sig = struct.pack("<HH", 0, 0xFFFF)
        self.assertIn(short_hdr_sig, lib_bytes)
        amd64_marker = struct.pack("<HHH", 0, 0xFFFF, 0) + struct.pack("<H", IMAGE_FILE_MACHINE_AMD64)
        self.assertIn(amd64_marker, lib_bytes)

    def test_generate_x86_import_lib(self):
        gen = ImportLibGenerator(self.info_x86)
        lib_bytes = gen.build_library_bytes()
        x86_marker = struct.pack("<HHH", 0, 0xFFFF, 0) + struct.pack("<H", IMAGE_FILE_MACHINE_I386)
        self.assertIn(x86_marker, lib_bytes)

    def test_generate_arm64_import_lib(self):
        gen = ImportLibGenerator(self.info_arm64)
        lib_bytes = gen.build_library_bytes()
        arm64_marker = struct.pack("<HHH", 0, 0xFFFF, 0) + struct.pack("<H", IMAGE_FILE_MACHINE_ARM64)
        self.assertIn(arm64_marker, lib_bytes)

    def test_write_lib_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "output.lib"
            gen = ImportLibGenerator(self.info_x64)
            written_path = gen.write_lib(out_file)

            self.assertTrue(written_path.is_file())
            content = written_path.read_bytes()
            self.assertTrue(content.startswith(b"!<arch>\n"))


if __name__ == "__main__":
    unittest.main()
