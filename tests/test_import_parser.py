import os
import unittest
from dll_forward_gen.pe_parser import PeParser


class TestImportParser(unittest.TestCase):
    def test_parse_imports_system_cmd_exe(self):
        cmd_exe = r"C:\Windows\System32\cmd.exe"
        if not os.path.exists(cmd_exe):
            self.skipTest("cmd.exe not found")

        parser = PeParser.from_file(cmd_exe)
        imports = parser.parse_imports()

        self.assertGreater(len(imports), 0)
        imported_dll_names = [imp.dll_name.lower() for imp in imports]

        # cmd.exe imports ntdll.dll
        self.assertTrue(any("ntdll" in name for name in imported_dll_names))

        ntdll_import = next(imp for imp in imports if "ntdll" in imp.dll_name.lower())
        self.assertGreater(len(ntdll_import.symbols), 0)

        sym_names = [s.name for s in ntdll_import.symbols if s.name]
        self.assertTrue(any("NtClose" in name or "RtlVirtualUnwind" in name for name in sym_names))

    def test_match_imports_against_dll(self):
        cmd_exe = r"C:\Windows\System32\cmd.exe"
        ntdll_dll = r"C:\Windows\System32\ntdll.dll"
        if not (os.path.exists(cmd_exe) and os.path.exists(ntdll_dll)):
            self.skipTest("binaries not found")

        cmd_parser = PeParser.from_file(cmd_exe)
        imports = cmd_parser.parse_imports()

        ntdll_parser = PeParser.from_file(ntdll_dll)
        ntdll_exports = ntdll_parser.parse()

        exported_names = {s.name for s in ntdll_exports.symbols if s.name}

        ntdll_import = next(imp for imp in imports if "ntdll" in imp.dll_name.lower())
        for sym in ntdll_import.symbols:
            if sym.name:
                self.assertIn(sym.name, exported_names)


if __name__ == "__main__":
    unittest.main()
