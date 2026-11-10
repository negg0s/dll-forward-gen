import json
import unittest
from pathlib import Path
import tempfile

from dll_forward_gen.batch import run_batch_config


class TestBatch(unittest.TestCase):
    def test_run_batch_config(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            cfg = {
                "output_dir": str(tmp_path / "batch_out"),
                "proxies": [
                    {
                        "dll": "version.dll",
                        "mode": "pragma",
                        "suffix": "_orig"
                    },
                    {
                        "dll": "version.dll",
                        "name": "version_masm",
                        "mode": "masm",
                        "file_log": True
                    }
                ]
            }
            cfg_file = tmp_path / "batch.json"
            cfg_file.write_text(json.dumps(cfg), encoding="utf-8")

            results = run_batch_config(cfg_file)
            self.assertEqual(len(results), 2)
            self.assertTrue((tmp_path / "batch_out" / "version_proxy" / "dllmain.cpp").exists())
            self.assertTrue((tmp_path / "batch_out" / "version_masm" / "stubs.asm").exists())


if __name__ == "__main__":
    unittest.main()
