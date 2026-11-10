import io
import os
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
        self.assertIn('"sections":', output)
        self.assertIn('"entropy":', output)
        self.assertIn('"hashes":', output)

    def test_cli_api_hash(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--api-hash", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("ROR13:", output)
        self.assertIn("DJB2:", output)
        self.assertIn("FNV1A:", output)
        self.assertIn("CRC32:", output)


    def test_cli_export_sdk(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = io.StringIO()
            with redirect_stdout(f):
                exit_code = main(["--export-sdk", tmp_dir])

            self.assertEqual(exit_code, 0)
            exported_files = list(Path(tmp_dir).glob("*.hpp"))
            self.assertGreaterEqual(len(exported_files), 12)
            file_names = {p.name for p in exported_files}
            self.assertIn("inline_hook.hpp", file_names)
            self.assertIn("pattern_scan.hpp", file_names)
            self.assertIn("iat_hook.hpp", file_names)
            self.assertIn("eat_hook.hpp", file_names)
            self.assertIn("veh_hook.hpp", file_names)
            self.assertIn("stealth.hpp", file_names)
            self.assertIn("lde.hpp", file_names)
            self.assertIn("pe_loader.hpp", file_names)
            self.assertIn("iat_resolver.hpp", file_names)
            self.assertIn("reloc.hpp", file_names)
            self.assertIn("api_hash.hpp", file_names)
            self.assertIn("syscall.hpp", file_names)

    def test_cli_tree_output(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--tree", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("DEPENDENCY & FORWARDING GRAPH", output)
        self.assertIn("Direct Imports", output)
        self.assertIn("Forwarded Export Targets", output)

    def test_cli_tls_callback_generation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "tls_proxy"
            exit_code = main([
                "version.dll",
                "-o", str(out_dir),
                "-m", "pragma",
                "--tls-callback",
                "--no-color",
            ])
            self.assertEqual(exit_code, 0)
            cpp_content = (out_dir / "dllmain.cpp").read_text(encoding="utf-8")
            self.assertIn(".CRT$XLB", cpp_content)
            self.assertIn("OnProxyTlsCallback", cpp_content)


    def test_cli_generate_lib(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            lib_out = Path(tmp_dir) / "version_test.lib"
            f = io.StringIO()
            with redirect_stdout(f):
                exit_code = main(["version.dll", "--lib", str(lib_out)])

            self.assertEqual(exit_code, 0)
            self.assertTrue(lib_out.is_file())
            content = lib_out.read_bytes()
            self.assertTrue(content.startswith(b"!<arch>\n"))


    def test_cli_search(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "-s", "GetFileVersionInfoA", "--dump-only", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("GetFileVersionInfoA", output)
        self.assertNotIn("VerFindFileA", output)


    def test_cli_manifest_extraction(self):
        system_cmd = r"C:\Windows\System32\cmd.exe"
        if not os.path.exists(system_cmd):
            self.skipTest("cmd.exe not available")

        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_file = Path(tmp_dir) / "cmd.manifest.xml"
            f = io.StringIO()
            with redirect_stdout(f):
                exit_code = main([system_cmd, "--manifest", str(manifest_file), "--no-color"])

            self.assertEqual(exit_code, 0)
            self.assertTrue(manifest_file.is_file())
            content = manifest_file.read_text(encoding="utf-8")
            self.assertIn("assembly", content)


    def test_cli_disasm(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--disasm", "GetFileVersionInfoA", "--no-color"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("GetFileVersionInfoA", output)
        self.assertIn("Raw Bytes:", output)
        self.assertIn("Pattern:", output)


if __name__ == "__main__":
    unittest.main()
