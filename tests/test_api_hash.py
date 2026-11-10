import unittest
from dll_forward_gen.api_hash import ror13, djb2, fnv1a, crc32_hash, compute_all_hashes


class TestApiHash(unittest.TestCase):
    def test_known_hashes(self):
        # Known pre-calculated values for GetFileVersionInfoA
        fn = "GetFileVersionInfoA"
        self.assertEqual(ror13(fn), 0x9D1DF4B3)
        self.assertEqual(djb2(fn), 0xD574F958)
        self.assertEqual(fnv1a(fn), 0x42D7EAD2)
        self.assertEqual(crc32_hash(fn), 0x5DE9D9BD)

    def test_compute_all_hashes(self):
        hashes = compute_all_hashes("LoadLibraryA")
        self.assertIn("ror13", hashes)
        self.assertIn("djb2", hashes)
        self.assertIn("fnv1a", hashes)
        self.assertIn("crc32", hashes)
        self.assertTrue(hashes["ror13"].startswith("0x"))
        self.assertEqual(len(hashes["ror13"]), 10)  # "0x" + 8 hex digits


if __name__ == "__main__":
    unittest.main()
