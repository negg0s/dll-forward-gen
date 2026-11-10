import unittest
from pathlib import Path
import tempfile

from dll_forward_gen.models import ExportSymbol, PeArch, PeExportInfo
from dll_forward_gen.generator import CodeGenerator, GeneratorMode


class TestHooking(unittest.TestCase):
    def setUp(self):
        self.symbols = [
            ExportSymbol(ordinal=1, rva=0x1000, name="FunctionAlpha"),
            ExportSymbol(ordinal=2, rva=0x1100, name="FunctionBeta"),
            ExportSymbol(ordinal=3, rva=0x1200, name="FunctionGamma"),
        ]
        self.info = PeExportInfo(
            filepath="target.dll",
            dll_name="target.dll",
            arch=PeArch.X64,
            timestamp=123,
            ordinal_base=1,
            symbols=self.symbols,
        )

    def test_masm_selective_hooking(self):
        gen = CodeGenerator(
            self.info,
            mode=GeneratorMode.MASM,
            hooked_symbols=["FunctionAlpha"],
        )
        asm_code, cpp_code, def_code = gen.generate_masm_sources()

        # FunctionAlpha should have a custom C++ hook, not a MASM blind jump
        self.assertIn("Hook_FunctionAlpha", cpp_code)
        self.assertIn("FunctionAlpha=Hook_FunctionAlpha @1", def_code)
        self.assertNotIn("proxy_FunctionAlpha proc", asm_code)

        # Unhooked functions should still be in MASM
        self.assertIn("proxy_FunctionBeta proc", asm_code)
        self.assertIn("FunctionBeta=proxy_FunctionBeta @2", def_code)


if __name__ == "__main__":
    unittest.main()
