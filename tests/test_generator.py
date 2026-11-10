import unittest
from pathlib import Path
import tempfile

from dll_forward_gen.models import ExportSymbol, PeArch, PeExportInfo
from dll_forward_gen.generator import CodeGenerator, GeneratorMode


class TestGenerator(unittest.TestCase):
    def setUp(self):
        self.symbols = [
            ExportSymbol(ordinal=1, rva=0x1000, name="FunctionAlpha"),
            ExportSymbol(ordinal=2, rva=0x1100, name="FunctionBeta"),
            ExportSymbol(ordinal=3, rva=0x1200, name=None),  # Ordinal-only
            ExportSymbol(
                ordinal=4,
                rva=0x1300,
                name="FunctionGamma",
                is_forwarded=True,
                forward_name="NTDLL.RtlAllocateHeap",
            ),
        ]
        self.info = PeExportInfo(
            filepath=r"C:\Windows\System32\target.dll",
            dll_name="target.dll",
            arch=PeArch.X64,
            timestamp=123456,
            ordinal_base=1,
            symbols=self.symbols,
        )

    def test_pragma_generation(self):
        gen = CodeGenerator(self.info, mode=GeneratorMode.PRAGMA, target_dll=r"C:\Windows\System32\target.dll")
        rendered = gen.generate_pragma_source()

        self.assertIn("#pragma comment(linker", rendered)
        self.assertIn("FunctionAlpha=C:\\\\Windows\\\\System32\\\\target.FunctionAlpha,@1", rendered)
        self.assertIn("FunctionBeta=C:\\\\Windows\\\\System32\\\\target.FunctionBeta,@2", rendered)
        self.assertIn("Ordinal_3=C:\\\\Windows\\\\System32\\\\target.#3,@3,NONAME", rendered)
        self.assertIn("DllMain", rendered)

    def test_suffix_modding_forwarding(self):
        # Local app modding: target forwards to target_orig.dll in same directory
        gen = CodeGenerator(self.info, mode=GeneratorMode.PRAGMA, target_dll="target_orig.dll")
        rendered = gen.generate_pragma_source()

        self.assertIn("FunctionAlpha=target_orig.FunctionAlpha,@1", rendered)
        self.assertNotIn("C:\\\\Windows\\\\System32", rendered)

    def test_file_logging_enabled(self):
        gen = CodeGenerator(self.info, mode=GeneratorMode.PRAGMA, enable_file_log=True)
        rendered = gen.generate_pragma_source()

        self.assertIn('fopen_s(&fLog, "proxy_log.txt", "a")', rendered)
        self.assertIn("[dll-forward-gen] Attached to process:", rendered)

    def test_def_generation(self):
        gen = CodeGenerator(self.info, mode=GeneratorMode.DEF, target_dll=r"C:\Windows\System32\target.dll")
        rendered_def = gen.generate_def_file()

        self.assertIn('LIBRARY "target.dll"', rendered_def)
        self.assertIn("EXPORTS", rendered_def)
        self.assertIn("FunctionAlpha=C:\\Windows\\System32\\target.FunctionAlpha @1", rendered_def)
        self.assertIn("FunctionBeta=C:\\Windows\\System32\\target.FunctionBeta @2", rendered_def)
        self.assertIn("Ordinal_3=C:\\Windows\\System32\\target.#3 @3 NONAME", rendered_def)

    def test_trampoline_generation(self):
        gen = CodeGenerator(self.info, mode=GeneratorMode.TRAMPOLINE, target_dll=r"C:\Windows\System32\target.dll")
        cpp_source, def_source = gen.generate_trampoline_sources()

        self.assertIn("LoadLibraryW", cpp_source)
        self.assertIn("GetProcAddress", cpp_source)
        self.assertIn("proxy_FunctionAlpha", cpp_source)
        self.assertIn("proxy_Ordinal_3", cpp_source)
        self.assertIn("FunctionAlpha=proxy_FunctionAlpha @1", def_source)
        self.assertIn("Ordinal_3=proxy_Ordinal_3 @3 NONAME", def_source)

    def test_project_emission_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir)
            gen = CodeGenerator(self.info, mode=GeneratorMode.PRAGMA, target_dll=r"C:\Windows\System32\target.dll")
            created_files = gen.emit_project(out_path)

            self.assertTrue((out_path / "dllmain.cpp").exists())
            self.assertTrue((out_path / "CMakeLists.txt").exists())
            self.assertTrue((out_path / "build.bat").exists())
            self.assertGreater(len(created_files), 0)


if __name__ == "__main__":
    unittest.main()
