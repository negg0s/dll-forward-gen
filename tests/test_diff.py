import unittest
from dll_forward_gen.models import ExportSymbol, PeArch, PeExportInfo
from dll_forward_gen.diff import diff_export_tables, ExportDiffResult


class TestDiff(unittest.TestCase):
    def setUp(self):
        s1 = [
            ExportSymbol(ordinal=1, rva=0x1000, name="FuncShared"),
            ExportSymbol(ordinal=2, rva=0x2000, name="FuncRemoved"),
            ExportSymbol(ordinal=3, rva=0x3000, name="FuncShifted"),
            ExportSymbol(ordinal=4, rva=0x4000, name=None),  # Ordinal 4
        ]
        s2 = [
            ExportSymbol(ordinal=1, rva=0x1000, name="FuncShared"),
            ExportSymbol(ordinal=5, rva=0x3500, name="FuncShifted"),  # Ordinal changed from 3 to 5!
            ExportSymbol(ordinal=6, rva=0x6000, name="FuncAdded"),     # Newly added!
            ExportSymbol(ordinal=4, rva=0x4000, name=None),
        ]
        self.info1 = PeExportInfo(
            filepath="v1.dll",
            dll_name="v1.dll",
            arch=PeArch.X64,
            timestamp=100,
            ordinal_base=1,
            symbols=s1,
        )
        self.info2 = PeExportInfo(
            filepath="v2.dll",
            dll_name="v2.dll",
            arch=PeArch.X64,
            timestamp=200,
            ordinal_base=1,
            symbols=s2,
        )

    def test_diff_detection(self):
        result = diff_export_tables(self.info1, self.info2)

        # Added
        added_names = [s.name for s in result.added]
        self.assertIn("FuncAdded", added_names)

        # Removed
        removed_names = [s.name for s in result.removed]
        self.assertIn("FuncRemoved", removed_names)

        # Modified (FuncShifted changed ordinal from 3 to 5)
        self.assertEqual(len(result.modified), 1)
        sym_old, sym_new = result.modified[0]
        self.assertEqual(sym_old.name, "FuncShifted")
        self.assertEqual(sym_old.ordinal, 3)
        self.assertEqual(sym_new.ordinal, 5)

        # Identical
        self.assertEqual(len(result.identical), 2)  # FuncShared and Ordinal 4

    def test_diff_formatting(self):
        result = diff_export_tables(self.info1, self.info2)
        formatted = result.format_report(use_color=False)

        self.assertIn("+ [ADDED]", formatted)
        self.assertIn("- [REMOVED]", formatted)
        self.assertIn("~ [MODIFIED]", formatted)
        self.assertIn("FuncAdded", formatted)
        self.assertIn("FuncRemoved", formatted)
        self.assertIn("FuncShifted", formatted)


if __name__ == "__main__":
    unittest.main()
