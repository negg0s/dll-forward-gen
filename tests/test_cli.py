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
            exit_code = main(["version.dll", "--dump-only"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn("VERSION.dll", output)
        self.assertIn("GetFileVersionInfoW", output)

    def test_cli_generate_pragma_project(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "version_proxy"
            exit_code = main(["version.dll", "-o", str(out_dir), "-m", "pragma"])

            self.assertEqual(exit_code, 0)
            self.assertTrue((out_dir / "dllmain.cpp").exists())
            self.assertTrue((out_dir / "CMakeLists.txt").exists())
            self.assertTrue((out_dir / "build.bat").exists())

    def test_cli_json_output(self):
        f = io.StringIO()
        with redirect_stdout(f):
            exit_code = main(["version.dll", "--json"])

        self.assertEqual(exit_code, 0)
        output = f.getvalue()
        self.assertIn('"dll_name":', output)
        self.assertIn('"symbols":', output)


if __name__ == "__main__":
    unittest.main()
