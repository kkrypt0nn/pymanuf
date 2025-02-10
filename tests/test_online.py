import unittest

from pymanuf.online import lookup


class Tests(unittest.TestCase):
    def test_d_link(self):
        self.assertEqual(lookup("C4:A8:1D:73:D7:8C"), "D-Link International")

    def test_netgear(self):
        self.assertEqual(lookup("9C:D3:6D:9A:CA:81"), "Netgear")

    def test_shanghai_broadwan_communications(self):
        self.assertEqual(
            lookup("40:ED:98:6F:DB:AC"), "Shanghai Broadwan Communications Co.,Ltd"
        )

    def test_piranha_ems(self):
        self.assertEqual(lookup("70:B3:D5:8C:CD:BE"), "Piranha EMS Inc.")

    def test_ieee_registration_authority(self):
        self.assertEqual(lookup("3C:24:F0:F0:BE:CF"), "IEEE Registration Authority")

    def test_samsung_electronics(self):
        self.assertEqual(lookup("24:FC:E5:AD:BB:89"), "Samsung Electronics Co.,Ltd")

    def test_invalid_address(self):
        with self.assertRaises(ValueError):
            lookup("G4:FC:E5:AD:BB:89")


if __name__ == "__main__":
    unittest.main()
