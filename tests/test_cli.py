import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
import tempfile

from dll_forward_gen.cli import main, resolve_dll_path


class TestCli(unittest.TestCase):
    def test_resolve_system_dll_by_name(self):
        resolved = resolve_dll_path("version.dll")
        self.assertTrue(resolved.is_file())
        self.assertEqual(resolved.name.lower(), "version.dll")

    def test_resolve_non_existent_dll_raises(self):
        with self.assertRaises(FileNotFoundError):
            resolve_dll_path("this_definitely_does_not_exist_12345.dll")

    def test_cli_dump_only(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--dump-only", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("VERSION.dll", output)
        self.assertIn("GetFileVersionInfoW", output)
        self.assertIn("SHA-256", output)
        self.assertIn("Mitigations", output)

    def test_cli_filter_by_name(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--filter", "QueryValue", "--dump-only", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("VerQueryValueW", output)
        self.assertNotIn("GetFileVersionInfoA", output)

    def test_cli_filter_by_ordinal(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--ordinal", "1", "--dump-only", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("@1", output)
        self.assertNotIn("@2", output)

    def test_cli_check_target(self):
        # cmd.exe imports ntdll.dll
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["ntdll.dll", "--check-target", r"C:\Windows\System32\cmd.exe", "--dump-only", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("TARGET IMPORT AUDIT", output)
        self.assertIn("COVERED", output)

    def test_cli_header_only_mode(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "version_forward.h"
            exit_code = main(["version.dll", "-H", "-o", str(out_file), "--no-color"])

            self.assertEqual(exit_code, 0)
            self.assertTrue(out_file.exists())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("#pragma once", content)
            self.assertIn("#pragma comment(linker", content)
            self.assertNotIn("DllMain", content)

    def test_cli_diff_mode(self):
        # Compare version.dll against itself (0 diff)
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--diff", "version.dll", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("EXPORT TABLE DIFF", output)
        self.assertIn("identical in both binaries", output)

    def test_cli_generate_suffix_project(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "version_mod_proxy"
            exit_code = main([
                "version.dll",
                "-o", str(out_dir),
                "-m", "pragma",
                "--suffix", "_orig",
                "--file-log",
                "--no-color",
            ])

            self.assertEqual(exit_code, 0)
            cpp_content = (out_dir / "dllmain.cpp").read_text(encoding="utf-8")
            self.assertIn("VERSION_orig", cpp_content)
            self.assertIn("proxy_log.txt", cpp_content)

    def test_cli_generate_masm_project(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "version_masm_proxy"
            exit_code = main([
                "version.dll",
                "-o", str(out_dir),
                "-m", "masm",
                "--no-color",
            ])

            self.assertEqual(exit_code, 0)
            self.assertTrue((out_dir / "stubs.asm").exists())
            self.assertTrue((out_dir / "dllmain.cpp").exists())
            self.assertTrue((out_dir / "exports.def").exists())

    def test_cli_json_output(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--json"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn('"dll_name":', output)
        self.assertIn('"symbols":', output)
        self.assertIn('"sha256":', output)
        self.assertIn('"mitigations":', output)


if __name__ == "__main__":
    unittest.main()
