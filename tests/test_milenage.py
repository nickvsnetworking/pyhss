import binascii
from unittest import TestCase

from milenage import Milenage


class MilenageTest(TestCase):
    def test_milenage_f2(self):
        # GIVEN
        expected_res = "5b510215e92efc47"
        ki = binascii.unhexlify("937EEEE6CE2C65D066DDE32BA79967ED")
        op_c = binascii.unhexlify("F4953DF2C4544E929CB5CFB3880E0AF8")
        rand = binascii.unhexlify("fe328a60e7108543f86f845884b842f8")

        # WHEN
        res = Milenage.f2(ki, rand, op_c)

        # THEN
        self.assertEqual(expected_res, res.hex())