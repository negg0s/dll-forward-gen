import unittest
from dll_forward_gen.known_ordinals import lookup_known_ordinal, WS2_32_ORDINALS, XLIVE_ORDINALS, OLEAUT32_ORDINALS


class TestKnownOrdinals(unittest.TestCase):
    def test_lookup_ws2_32(self):
        self.assertEqual(lookup_known_ordinal("ws2_32.dll", 1), "accept")
        self.assertEqual(lookup_known_ordinal("WS2_32.DLL", 4), "connect")
        self.assertEqual(lookup_known_ordinal(r"C:\Windows\System32\ws2_32.dll", 23), "socket")
        self.assertEqual(lookup_known_ordinal("ws2_32.dll", 115), "WSAStartup")

    def test_lookup_xlive(self):
        self.assertEqual(lookup_known_ordinal("xlive.dll", 1), "XLiveInitialize")
        self.assertEqual(lookup_known_ordinal("xlive.dll", 5000), "XLivePBufferAllocate_5000")

    def test_lookup_oleaut32(self):
        self.assertEqual(lookup_known_ordinal("oleaut32.dll", 2), "SysAllocString")
        self.assertEqual(lookup_known_ordinal("oleaut32.dll", 8), "VariantInit")

    def test_lookup_unknown(self):
        self.assertIsNone(lookup_known_ordinal("kernel32.dll", 9999))
        self.assertIsNone(lookup_known_ordinal("nonexistent.dll", 1))


if __name__ == "__main__":
    unittest.main()
