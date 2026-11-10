import unittest
from pathlib import Path
import tempfile

from dll_forward_gen.models import ExportSymbol, PeArch, PeExportInfo
from dll_forward_gen.generator import CodeGenerator, GeneratorMode


class TestMasmGenerator(unittest.TestCase):
    def setUp(self):
        self.symbols = [
            ExportSymbol(ordinal=1, rva=0x1000, name="FunctionAlpha"),
            ExportSymbol(ordinal=2, rva=0x1100, name="FunctionBeta"),
            ExportSymbol(ordinal=3, rva=0x1200, name=None),  # Ordinal-only
        ]
        self.info_x64 = PeExportInfo(
            filepath=r"C:\Windows\System32\target.dll",
            dll_name="target.dll",
            arch=PeArch.X64,
            timestamp=123456,
            ordinal_base=1,
            symbols=self.symbols,
        )
        self.info_x86 = PeExportInfo(
            filepath=r"C:\Windows\SysWOW64\target.dll",
            dll_name="target.dll",
            arch=PeArch.X86,
            timestamp=123456,
            ordinal_base=1,
            symbols=self.symbols,
        )

    def test_masm_x64_generation(self):
        gen = CodeGenerator(self.info_x64, mode=GeneratorMode.MASM)
        asm_code, cpp_code, def_code = gen.generate_masm_sources()

        # Check ASM directives
        self.assertIn(".code", asm_code)
        self.assertIn("extern g_pfn_FunctionAlpha : qword", asm_code)
        self.assertIn("extern g_pfn_Ordinal_3 : qword", asm_code)
        self.assertIn("jmp qword ptr [g_pfn_FunctionAlpha]", asm_code)
        self.assertIn("proxy_FunctionAlpha proc", asm_code)
        self.assertIn("proxy_FunctionAlpha endp", asm_code)

        # Check C++ loader
        self.assertIn("FARPROC g_pfn_FunctionAlpha = NULL;", cpp_code)
        self.assertIn("GetProcAddress", cpp_code)
        self.assertIn("LoadLibraryW", cpp_code)

        # Check DEF mapping
        self.assertIn("FunctionAlpha=proxy_FunctionAlpha @1", def_code)
        self.assertIn("Ordinal_3=proxy_Ordinal_3 @3 NONAME", def_code)

    def test_masm_x86_generation(self):
        gen = CodeGenerator(self.info_x86, mode=GeneratorMode.MASM)
        asm_code, _, _ = gen.generate_masm_sources()

        self.assertIn(".model flat", asm_code)
        self.assertIn("extern g_pfn_FunctionAlpha : dword", asm_code)
        self.assertIn("jmp dword ptr [g_pfn_FunctionAlpha]", asm_code)

    def test_masm_project_emission(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir)
            gen = CodeGenerator(self.info_x64, mode=GeneratorMode.MASM)
            created = gen.emit_project(out_path)

            self.assertTrue((out_path / "stubs.asm").exists())
            self.assertTrue((out_path / "dllmain.cpp").exists())
            self.assertTrue((out_path / "exports.def").exists())
            self.assertTrue((out_path / "CMakeLists.txt").exists())
            self.assertTrue((out_path / "build.bat").exists())
            self.assertEqual(len(created), 5)


if __name__ == "__main__":
    unittest.main()
