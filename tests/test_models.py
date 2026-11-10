import unittest
from dll_forward_gen.models import ExportSymbol, PeArch, PeExportInfo


class TestModels(unittest.TestCase):
    def test_pe_arch_from_machine(self):
        self.assertEqual(PeArch.from_machine(0x014C), PeArch.X86)
        self.assertEqual(PeArch.from_machine(0x8664), PeArch.X64)
        self.assertEqual(PeArch.from_machine(0xAA64), PeArch.ARM64)
        self.assertEqual(PeArch.from_machine(0x9999), PeArch.UNKNOWN)

    def test_export_symbol_named(self):
        sym = ExportSymbol(ordinal=1, rva=0x1000, name="GetFileVersionInfoW")
        self.assertFalse(sym.is_ordinal_only)
        self.assertEqual(sym.safe_name, "GetFileVersionInfoW")
        self.assertFalse(sym.is_forwarded)
        self.assertIn("[@1] GetFileVersionInfoW", str(sym))

    def test_export_symbol_ordinal_only(self):
        sym = ExportSymbol(ordinal=42, rva=0x2000, name=None)
        self.assertTrue(sym.is_ordinal_only)
        self.assertEqual(sym.safe_name, "Ordinal_42")
        self.assertIn("<ordinal-only>", str(sym))

    def test_export_symbol_forwarded(self):
        sym = ExportSymbol(
            ordinal=5,
            rva=0x3050,
            name="RtlAllocateHeap",
            is_forwarded=True,
            forward_name="NTDLL.RtlAllocateHeap",
        )
        self.assertTrue(sym.is_forwarded)
        self.assertEqual(sym.forward_name, "NTDLL.RtlAllocateHeap")
        self.assertIn("-> NTDLL.RtlAllocateHeap", str(sym))

    def test_pe_export_info_properties(self):
        s1 = ExportSymbol(ordinal=1, rva=0x1000, name="FuncA")
        s2 = ExportSymbol(ordinal=2, rva=0x1100, name=None)
        s3 = ExportSymbol(ordinal=3, rva=0x1200, name="FuncB", is_forwarded=True, forward_name="FOO.Bar")

        info = PeExportInfo(
            filepath="C:/dummy.dll",
            dll_name="dummy.dll",
            arch=PeArch.X64,
            timestamp=12345678,
            ordinal_base=1,
            symbols=[s1, s2, s3],
        )

        self.assertEqual(info.total_count, 3)
        self.assertEqual(len(info.named_exports), 2)
        self.assertEqual(len(info.ordinal_only_exports), 1)
        self.assertEqual(len(info.forwarded_exports), 1)


if __name__ == "__main__":
    unittest.main()
