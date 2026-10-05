# Copyright 2022-2023 Nick <nick@nickvsnetworking.com>
# Copyright 2023 David Kneipp <david@davidkneipp.com>
# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import unittest
import logging
global log
log= logging.getLogger("UnitTestLogger")
import diameter as DiameterLib
from logtool import LogTool
from pyhss_config import config


class Diameter_Tests(unittest.TestCase):
    diameter_inst = 0
    Diameter_CER = b"\x01\x00\x01P\x80\x00\x01\x01\x00\x00\x00\x00\x8e\xb7\xd5j\xb0{\xcd\xd6\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x01@\x00\x00\x0e\x00\x01\x7f\x00\x01\x01\x00\x00\x00\x00\x01\n@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x01\r\x00\x00\x00\x14PyHSS-client\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00#\x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x16\x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00'\x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x01\x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x00\x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\xff\xff\xff\xff\x00\x00\x01\t@\x00\x00\x0c\x00\x00\x15\x9f\x00\x00\x01\t@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\t@\x00\x00\x0c\x00\x002\xdb"
    Diameter_DWR = b'\x01\x00\x00P\x80\x00\x01\x18\x00\x00\x00\x00x\xb7\x96\x8du\xb2+\xf3\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00'
    Diameter_DPR = b'0100008c8000011a000000009aeff2238170f971000001084000003a696c7363303364737230312e6d766e6f2e6570632e6d6e633538382e6d63633331312e336770706e6574776f726b2e6f72670000000001284000002e6d766e6f2e6570632e6d6e633538382e6d63633331312e336770706e6574776f726b2e6f72670000000001114000000c00000000'
    Diameter_AIR = b"\x01\x00\x01\x14\xc0\x00\x01>\x01\x00\x00#0\xd0hym\x19i\xc8\x00\x00\x01\x07@\x00\x00'6873733031;3076d64228;1;app_s6a\x00\x00\x00\x01\x15@\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00\x1cnickvsnetworking.com\x00\x00\x00\x01@\x00\x00\x17505931111111116\x00\x00\x00\x05\x80\xc0\x00\x00,\x00\x00(\xaf\x00\x00\x05\x82\xc0\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x01\x00\x00\x05\x84\xc0\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x01\x00\x00\x05\x7f\xc0\x00\x00\x0f\x00\x00(\xaf\x05\xf59\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00#"
    Diameter_ULR = b"\x01\x00\x01\x18\xc0\x00\x01<\x01\x00\x00#\xa2\xd9\xb6\\\xe9!\xf7\xfa\x00\x00\x01\x07@\x00\x00'6873733031;c78c1d986e;1;app_s6a\x00\x00\x00\x01\x15@\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00\x1cnickvsnetworking.com\x00\x00\x00\x01@\x00\x00\x17505931111111116\x00\x00\x00\x04\x08\x80\x00\x00\x10\x00\x00(\xaf\x00\x00\x03\xec\x00\x00\x05}\xc0\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x02\x00\x00\x05\x7f\xc0\x00\x00\x0f\x00\x00(\xaf\x05\xf59\x00\x00\x00\x06O\x80\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00#"
    Diameter_PUR = b"\x01\x00\x00\xc4\xc0\x00\x01A\x01\x00\x00#\xf2\xdc\x8e/\xf6*\xfa\xe1\x00\x00\x01\x07@\x00\x00'6873733031;485307f5f1;1;app_s6a\x00\x00\x00\x01\x15@\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00\x08\x00\x00\x00\x01@\x00\x00\x17505931111111116\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00#"
    Diameter_CLR = b"\x01\x00\x00\xd4\xc0\x00\x01=\x01\x00\x00#\xcd\x17\xde\xfd@j7\xee\x00\x00\x01\x07@\x00\x00'6873733031;ed09a5fb06;1;app_s6a\x00\x00\x00\x01\x15@\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00\x08\x00\x00\x00\x01@\x00\x00\x17505931111111116\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00#\x00\x00\x05\x8c\xc0\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x02"
    Diameter_DPR = b'\x01\x00\x00\\\x80\x00\x01\x1a\x00\x00\x00\x007%\x1fT\x13j\xdf\x14\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x11@\x00\x00\x0c\x00\x00\x00\x00'


    Diameter_Cx_MAA = b'\x01\x00\x01h\xc0\x00\x01/\x01\x00\x00\x00\xc1Dg\xeb\xdd\xeebn\x00\x00\x01\x07@\x00\x00&6873733031;53ca4d5113;1;app_cx\x00\x00\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00\x13localdomain\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x00\x00\x00\x01\x15@\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00\x01@\x00\x00,505931111111116@nickvsnetworking.com\x00\x00\x02Y\xc0\x00\x004\x00\x00(\xafsip:505931111111116@nickvsnetworking.com\x00\x00\x02_\xc0\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x01\x00\x00\x02d\xc0\x00\x00(\x00\x00(\xaf\x00\x00\x02`\xc0\x00\x00\x1c\x00\x00(\xafDigest-AKAv1-MD5\x00\x00\x02Z\xc0\x00\x00\x18\x00\x00(\xafPyHSS-client'
    Diameter_Cx_UAR = b'\x01\x00\x018\xc0\x00\x01,\x01\x00\x00\x00g|%\xa6\x92h!\xea\x00\x00\x01\x07@\x00\x00&6873733031;d01955b4ab;1;app_cx\x00\x00\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00\x13localdomain\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x00\x00\x00\x01\x15@\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00\x01@\x00\x00,505931111111116@nickvsnetworking.com\x00\x00\x02Y\xc0\x00\x004\x00\x00(\xafsip:505931111111116@nickvsnetworking.com\x00\x00\x02X\xc0\x00\x00 \x00\x00(\xafnickvsnetworking.com'
    Diameter_Cx_SAR = b'\x01\x00\x01p\xc0\x00\x01-\x01\x00\x00\x00\x8b(\xf6\x1b\xd2\x1df\xc4\x00\x00\x01\x07@\x00\x00&6873733031;805d6d645b;1;app_cx\x00\x00\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00\x13localdomain\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x00\x00\x00\x01\x15@\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x02Y\xc0\x00\x004\x00\x00(\xafsip:505931111111116@nickvsnetworking.com\x00\x00\x02Z\xc0\x00\x007\x00\x00(\xafsip:scscf.mnc001.mcc01.3gppnetwork.org:5060\x00\x00\x00\x00\x01@\x00\x00,505931111111116@nickvsnetworking.com\x00\x00\x02f\xc0\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x01\x00\x00\x02p\xc0\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x00'
    Diameter_Cx_RTR = b'\x01\x00\x01\xc4\xc0\x00\x010\x01\x00\x00\x00\x8c\xbb\xca\xee-;j"\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00#\x00\x00\x01\x07@\x00\x00&6873733031;89382efa9e;1;app_cx\x00\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x00\x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x08@\x00\x00\rhss01\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc001.mcc001.3gppnetwork.org\x00\x00\x00\x00\x00\x02g\xc0\x00\x004\x00\x00(\xaf\x00\x00\x02h\xc0\x00\x00\x10\x00\x00(\xaf\x00\x00\x00\x00\x00\x00\x02i\xc0\x00\x00\x17\x00\x00(\xafTest Reason\x00\x00\x00\x01\x1b@\x00\x00\x13localdomain\x00\x00\x00\x01%@\x00\x00\x17hss.localdomain\x00\x00\x00\x01\x15@\x00\x00\x0c\x00\x00\x00\x01\x00\x00\x00\x01@\x00\x00,505931111111116@nickvsnetworking.com\x00\x00\x02Y\xc0\x00\x004\x00\x00(\xafsip:505931111111116@nickvsnetworking.com\x00\x00\x02Z\xc0\x00\x00\x18\x00\x00(\xafPyHSS-client\x00\x00\x01\x1c@\x00\x00(\x00\x00\x01\x18@\x00\x00\x13localdomain\x00\x00\x00\x00!@\x00\x00\n\x00\x01\x00\x00\x00\x00\x01\x1a@\x00\x00\x13localdomain\x00'

    #Test IMSI - 505931111111116

    def test_A_Instantiate(self):
        diameter_inst = DiameterLib.Diameter(
            LogTool(config),
            str('OriginHost'), str('OriginRealm'), 
            str('UnitTest_Diameter'), str('001'), str('001')
        )
        log.debug("Instantiated Diameter Class")
        self.__class__.diameter_inst = diameter_inst
        self.assertEqual(isinstance(diameter_inst, DiameterLib.Diameter), True, "Created Class OK")
        
    def test_B_Recv_CER_CmdCode(self):
        packet_vars, avps = self.__class__.diameter_inst.decode_diameter_packet(self.__class__.Diameter_CER)
        log.debug("Received request with Command Code: " + str(packet_vars['command_code']) + ", ApplicationID: " + str(packet_vars['ApplicationId']) + " and flags " + str(packet_vars['flags']))
        self.assertEqual(packet_vars['command_code'], 257, "Command Code Mismatch")

    def test_B_Recv_CER_ApplicationID(self):
        packet_vars, avps = self.__class__.diameter_inst.decode_diameter_packet(self.__class__.Diameter_CER)
        self.assertEqual(packet_vars['ApplicationId'], 0, "Application ID Mismatch")

    def test_B_Recv_AIR(self):
        packet_vars, avps = self.__class__.diameter_inst.decode_diameter_packet(self.__class__.Diameter_AIR)
        assert packet_vars == {
            "ApplicationId": 16777251,
            "command_code": 318,
            "end-to-end-identifier": "6d1969c8",
            "flags": "c0",
            "flags_bin": "11000000",
            "hop-by-hop-identifier": "30d06879",
            "length": 276,
            "packet_version": "01",
        }

    def test_C_TBCD_encode_even_length(self):
        self.assertEqual(self.__class__.diameter_inst.TBCD_encode("491701234567"), "947110325476")

    def test_C_TBCD_encode_odd_length(self):
        self.assertEqual(self.__class__.diameter_inst.TBCD_encode("4917012345678"), "947110325476f8")

    def test_C_TBCD_encode_special_chars(self):
        self.assertEqual(self.__class__.diameter_inst.TBCD_encode("123#"), "21b3")

    def test_C_TBCD_encode_decode_roundtrip(self):
        msisdn = "262423403000001"
        encoded = self.__class__.diameter_inst.TBCD_encode(msisdn)
        self.assertEqual(bytes.fromhex(encoded).hex(), encoded, "TBCD_encode must return valid hex")
        self.assertEqual(self.__class__.diameter_inst.TBCD_decode(encoded), msisdn)

    def test_C_TBCD_encode_rejects_non_tbcd_input(self):
        # A subscriber without an MSISDN used to be encoded as str(None) == "None",
        # embedding the non-hex text "oNen" in the outbound message and crashing
        # bytes.fromhex() in diameterService.py.
        for bad_input in (str(None), "12x4", "+491701234567"):
            with self.assertRaises(ValueError, msg=f"TBCD_encode must reject {bad_input!r}"):
                self.__class__.diameter_inst.TBCD_encode(bad_input)

    def test_C_SLh_RIR_without_msisdn_is_valid_hex(self):
        # msisdn=None must be treated as absent, not TBCD-encoded as "None"
        for kwargs in ({"imsi": "505931111111116", "msisdn": None}, {"imsi": "505931111111116"}):
            packet = self.__class__.diameter_inst.Request_16777291_8388622(**kwargs)
            bytes.fromhex(packet)

    def test_C_Sh_UDR_without_msisdn_is_valid_hex(self):
        # msisdn=None must be treated as absent, not TBCD-encoded as "None"
        for kwargs in ({"imsi": "505931111111116", "msisdn": None}, {"imsi": "505931111111116"}):
            packet = self.__class__.diameter_inst.Request_16777217_306(**kwargs)
            bytes.fromhex(packet)

    def _decode_sh_udr(self, user_identity_avp):
        # Builds a UDR around the given User-Identity AVP and decodes it, like diameterService does
        diameter_inst = self.__class__.diameter_inst
        avp = diameter_inst.generate_avp(263, 40, b"pcscf;1;app_sh".hex())
        avp += diameter_inst.generate_avp(264, 40, diameter_inst.OriginHost)
        avp += diameter_inst.generate_avp(296, 40, diameter_inst.OriginRealm)
        avp += user_identity_avp
        packet = diameter_inst.generate_diameter_packet("01", "c0", 306, 16777217, "00000001", "00000001", avp)
        return diameter_inst.decode_diameter_packet(packet)

    def _user_identity(self, msisdn=None, public_identity=None):
        diameter_inst = self.__class__.diameter_inst
        content = ""
        if msisdn is not None:
            content += diameter_inst.generate_vendor_avp(701, "c0", 10415, diameter_inst.TBCD_encode(msisdn))
        if public_identity is not None:
            content += diameter_inst.generate_vendor_avp(601, "c0", 10415, public_identity.encode().hex())
        return diameter_inst.generate_vendor_avp(700, "c0", 10415, content)

    def test_D_Sh_identities_msisdn_then_public_identity(self):
        # Both identities are returned, MSISDN first, so a failed MSISDN lookup can fall back
        _, avps = self._decode_sh_udr(self._user_identity(
            msisdn="4917012345678", public_identity="sip:262423403000001@ims.mnc001.mcc001.3gppnetwork.org"))
        self.assertEqual(self.__class__.diameter_inst.getShUserIdentities(avps),
                         [("msisdn", "4917012345678"), ("imsi", "262423403000001")])

    def test_D_Sh_identities_tel_uri(self):
        # The + is kept, Get_IMS_Subscriber matches the MSISDN with or without it
        _, avps = self._decode_sh_udr(self._user_identity(public_identity="tel:+4917012345678"))
        self.assertEqual(self.__class__.diameter_inst.getShUserIdentities(avps), [("msisdn", "+4917012345678")])

    def test_D_Sh_lookup_falls_back_to_public_identity(self):
        # A Public-Identity next to an unknown MSISDN must still find the subscriber
        class FakeDatabase:
            def Get_IMS_Subscriber(self, **kwargs):
                if "imsi" not in kwargs:
                    raise ValueError("No row was found")
                return {"imsi": kwargs["imsi"]}

            def Get_Subscriber(self, **kwargs):
                return self.Get_IMS_Subscriber(**kwargs)

        diameter_inst = self.__class__.diameter_inst
        database = diameter_inst.database
        diameter_inst.database = FakeDatabase()
        try:
            ims_subscriber, subscriber = diameter_inst.getShSubscriber(
                [("msisdn", "4917012345678"), ("imsi", "262423403000001")])
        finally:
            diameter_inst.database = database
        self.assertEqual(ims_subscriber, {"imsi": "262423403000001"})
        self.assertEqual(subscriber, {"imsi": "262423403000001"})

    def test_D_Sh_UDR_ungrouped_user_identity_is_rejected(self):
        # A User-Identity carrying the MSISDN directly instead of sub-AVPs gets 5004 and Failed-AVP
        diameter_inst = self.__class__.diameter_inst
        raw_msisdn = diameter_inst.TBCD_encode("4917012345678")
        packet_vars, avps = self._decode_sh_udr(diameter_inst.generate_vendor_avp(700, "c0", 10415, raw_msisdn))
        _, answer_avps = diameter_inst.decode_diameter_packet(diameter_inst.Answer_16777217_306(packet_vars, avps))
        self.assertEqual(diameter_inst.get_avp_data(answer_avps, 268), [diameter_inst.int_to_hex(5004, 4)])
        failed_avp = diameter_inst.get_avp_data(answer_avps, 279)[0]
        self.assertEqual([(a["avp_code"], a["misc_data"]) for a in failed_avp], [(700, raw_msisdn)])
