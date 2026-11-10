import unittest
from pathlib import Path
import tempfile

from dll_forward_gen.models import ExportSymbol, PeArch, PeExportInfo
from dll_forward_gen.generator import CodeGenerator, GeneratorMode


class TestHeaderOnly(unittest.TestCase):
    def setUp(self):
        symbols = [
            ExportSymbol(ordinal=1, rva=0x1000, name="FuncOne"),
            ExportSymbol(ordinal=2, rva=0x2000, name="FuncTwo"),
        ]
        self.info = PeExportInfo(
            filepath="foo.dll",
            dll_name="foo.dll",
            arch=PeArch.X64,
            timestamp=123,
            ordinal_base=1,
            symbols=symbols,
        )

    def test_generate_header_only(self):
        gen = CodeGenerator(self.info, target_dll=r"C:\Windows\System32\foo.dll")
        hdr_src = gen.generate_header_only_source()

        self.assertIn("#pragma once", hdr_src)
        self.assertIn("#pragma comment(linker", hdr_src)
        self.assertIn("FuncOne=C:\\\\Windows\\\\System32\\\\foo.FuncOne,@1", hdr_src)
        self.assertIn("FuncTwo=C:\\\\Windows\\\\System32\\\\foo.FuncTwo,@2", hdr_src)
        # Should NOT contain DllMain because it is meant to be included in an existing project
        self.assertNotIn("BOOL APIENTRY DllMain", hdr_src)


if __name__ == "__main__":
    unittest.main()
