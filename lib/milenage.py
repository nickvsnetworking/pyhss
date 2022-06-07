"""
Copyright (c) 2016-present, Facebook, Inc.
All rights reserved.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree. An additional grant
of patent rights can be found in the PATENTS file in the same directory.
"""

import hmac
from Crypto.Cipher import AES
from Crypto.Random import random

from lte import BaseLTEAuthAlgo

import logging
import logtool
logtool = logtool.LogTool()
import os
import sys
sys.path.append(os.path.realpath('../'))

CryptoLogger = logging.getLogger('CryptoLogger')


class Milenage(BaseLTEAuthAlgo):
    """
    Milenage Algorithm (3GPP TS 35.205, .206, .207, .208)
    """

    def generate_eutran_vector(self, key, opc, sqn, plmn):
        """
        Generate the E-EUTRAN key vector.
        Args:
            key (bytes): 128 bit subscriber key
            opc (bytes): 128 bit operator variant algorithm configuration field
            sqn (int): 48 bit sequence number
            plmn (bytes): 24 bit network identifer
                Octet           Description
                  1      MCC digit 2 | MCC digit 1
                  2      MNC digit 3 | MCC digit 3
                  3      MNC digit 2 | MNC digit 1
        Returns:
            rand (bytes): 128 bit random challenge
            xres (bytes): 128 bit expected result
            autn (bytes): 128 bit authentication token
            kasme (bytes): 256 bit base network authentication code
        """
        CryptoLogger.debug("Called milenage.generate_eutran_vector")

        CryptoLogger.debug("Generating SQN bytes")
        CryptoLogger.debug("Current SQN value is " + str(sqn) + " and is " + str(len(str(sqn))) + " long")
        sqn_bytes = bytearray.fromhex('{:012x}'.format(sqn))
        #With some inputs a space is added here.
        #See https://stackoverflow.com/questions/57697983/how-do-i-interpret-spaces-in-python-byte-arrays
        CryptoLogger.debug("Generated SQN bytes")
        CryptoLogger.debug("SQN bytes is " + str(sqn_bytes))

        CryptoLogger.debug("Generating rand")
        rand = Milenage.generate_rand()
        CryptoLogger.debug("Generated rand")

        CryptoLogger.debug("Generating f1")
        mac_a, _ = Milenage.f1(key, sqn_bytes, rand, opc, self.amf)
        CryptoLogger.debug("Generated f1")
        CryptoLogger.debug("Generating f2")
        xres, ak = Milenage.f2_f5(key, rand, opc)
        CryptoLogger.debug("Generated f2")
        CryptoLogger.debug("Generating f3")
        ck = Milenage.f3(key, rand, opc)
        CryptoLogger.debug("Generated f3")
        CryptoLogger.debug("Generating f4")
        ik = Milenage.f4(key, rand, opc)
        CryptoLogger.debug("Generated f4")

        CryptoLogger.debug("Generate generate_autn")
        autn = Milenage.generate_autn(sqn_bytes, ak, mac_a, self.amf)
        CryptoLogger.debug("Generated generate_autn")
        CryptoLogger.debug("Generate generate_kasme")
        kasme = Milenage.generate_kasme(ck, ik, plmn, sqn_bytes, ak)
        CryptoLogger.debug("Generated generate_kasme")
        CryptoLogger.debug("Successfully ran milenage.generate_eutran_vector")
        return rand, xres, autn, kasme


    def generate_maa_vector(self, key, opc, sqn, plmn):
        """
        Generate the E-EUTRAN key vector.
        Args:
            key (bytes): 128 bit subscriber key
            opc (bytes): 128 bit operator variant algorithm configuration field
            sqn (int): 48 bit sequence number
            plmn (bytes): 24 bit network identifer
                Octet           Description
                  1      MCC digit 2 | MCC digit 1
                  2      MNC digit 3 | MCC digit 3
                  3      MNC digit 2 | MNC digit 1
        Returns:
            rand (bytes): 128 bit random challenge
            xres (bytes): 128 bit expected result
            autn (bytes): 128 bit authentication token
            kasme (bytes): 256 bit base network authentication code
        """
        CryptoLogger.debug("Called milenage.generate_maa_vector")

        CryptoLogger.debug("Generating SQN bytes")
        CryptoLogger.debug("Current SQN value is " + str(sqn) + " and is " + str(len(str(sqn))) + " long")
        sqn_bytes = bytearray.fromhex('{:012x}'.format(sqn))
        #With some inputs a space is added here.
        #See https://stackoverflow.com/questions/57697983/how-do-i-interpret-spaces-in-python-byte-arrays
        CryptoLogger.debug("Generated SQN bytes")
        CryptoLogger.debug("SQN bytes is " + str(sqn_bytes))

        CryptoLogger.debug("Generating rand")
        rand = Milenage.generate_rand()
        CryptoLogger.debug("Generated rand")

        CryptoLogger.debug("Generating f1")
        mac_a, _ = Milenage.f1(key, sqn_bytes, rand, opc, self.amf)
        CryptoLogger.debug("Generated f1")


        CryptoLogger.debug("Generating f2")
        xres, ak = Milenage.f2_f5(key, rand, opc)
        CryptoLogger.debug("Generated f2")

        CryptoLogger.debug("Generating ck")
        ck = Milenage.f3(key, rand, opc)
        CryptoLogger.debug("Generating ik")
        ik = Milenage.f4(key, rand, opc)


        CryptoLogger.debug("Generate generate_autn")
        autn = Milenage.generate_autn(sqn_bytes, ak, mac_a, self.amf)

        return rand, xres, autn, ck, ik


    def generate_auts(self, key, opc, rand, sqn):
        """
        Compute AUTS for re-synchronization using the formula
            AUTS = SQN_MS ^ AK || f1*(SQN_MS || RAND || AMF*)
        Args:
            key (bytes): 128 bit subscriber key
            opc (bytes): 128 bit operator variant algorithm configuration field
            rand (bytes): 128 bit random challenge
            sqn (int), 48 bit sequence number
        Returns:
            auts (bytes): 112 bit authentication token
        """
        ak = self.f5_star(key, rand, opc)
        sqn_bytes = bytearray.fromhex('{:012x}'.format(sqn))
        _, mac_s = self.f1(key, sqn_bytes, rand, opc, self.amf)
        return xor(sqn_bytes, ak) + mac_s

    def generate_resync(self, auts, key, opc, rand):
        """
        Compute SQN_MS and MAC-S from AUTS for re-synchronization
            AUTS = SQN_MS ^ AK || f1*(SQN_MS || RAND || AMF*)
        Args:
            auts (bytes): 112 bit authentication token from client key
            opc (bytes): 128 bit operator variant algorithm configuration field
            key (bytes): 128 bit subscriber key
            rand (bytes): 128 bit random challenge
        Returns:
            sqn_ms (int), 48 bit sequence number from client
            mac_s (bytes), 64 bit resync authentication code
        """
        #print("key is: " + str(type(key)) + " and has length of " + str(len(key)))
        #print("rand is: " + str(type(rand)) + " and has length of " + str(len(rand)))
        #print("opc is: " + str(type(opc)) + " and has length of " + str(len(opc)))
        ak = self.f5_star(key, rand, opc)
        #print("AK is: " + str(type(ak)) + " and has length of " + str(len(ak)))
        sqn_ms = xor(auts[:6], ak)
        sqn_ms_int = int.from_bytes(sqn_ms, byteorder='big')
        _, mac_s = self.f1(key, sqn_ms, rand, opc, self.amf)
        return sqn_ms_int, mac_s

    @classmethod
    def f1(cls, key, sqn, rand, opc, amf):
        """
        Implementation of f1 and f1*, the network authentication function and
        the re-synchronisation message authentication function according to
        3GPP 35.206 4.1

        Args:
            key (bytes): 128 bit subscriber key
            sqn (bytes): 48 bit sequence number
            rand (bytes): 128 bit random challenge
            opc (bytes): 128 bit computed from OP and subscriber key
            amf (bytes): 16 bit authentication management field
        Returns:
            (64 bit Network auth code, 64 bit Resynch auth code)
        """
        # TEMP = E_K(RAND XOR OP_C)
        temp = cls.encrypt(key, xor(rand, opc))

        # IN1 = SQN || AMF || SQN || AMF
        in1 = (sqn[0:6] + amf[0:2]) * 2

        # Constants from 3GPP 35.206 4.1
        c1 = 16 * b'\x00'  # some constant
        r1 = 8  # rotate by 8 bytes

        # OUT1 = E_K(TEMP XOR rotate(IN1 XOR OP_C, r1) XOR c1) XOR OP_C
        out1_ = cls.encrypt(key, xor(temp, rotate(xor(in1, opc), r1)), c1)
        out1 = xor(opc, out1_)

        #  MAC-A = f1 = OUT1[0] .. OUT1[63]
        #  MAC-S = f1* = OUT1[64] .. OUT1[127]
        return out1[:8], out1[8:]

    @classmethod
    def f2_f5(cls, key, rand, opc):
        """
        Implementation of f2 and f5, the compute anonymity key and response to
        challenge functions according to 3GPP 35.206 4.1

        Args:
            key (bytes): 128 bit subscriber key
            rand (bytes): 128 bit random challenge
            opc (bytes): 128 bit computed from OP and subscriber key
        Returns:
            (xres, ak) = (64 bit response to challenge, 48 bit anonymity key)
        """
        # Constants from 3GPP 35.206 4.1
        c2 = 15 * b'\x00' + b'\x01'  # some constant
        r2 = 0  # rotate by 0 bytes

        # TEMP = E_K(RAND XOR OP_C)
        # OUT2 = E_K(rotate(TEMP XOR OP_C, r2) XOR c2) XOR OP_C
        temp_x_opc = xor(cls.encrypt(key, xor(rand, opc)), opc)
        out2 = xor(cls.encrypt(key, xor(rotate(temp_x_opc, r2), c2)), opc)
        # res = f2 = OUT2[64] ... OUT2[127]
        # ak = f5 = OUT2[0] ... OUT2[47]
        return out2[8:16], out2[0:6]

    @classmethod
    def f3(cls, key, rand, opc):
        """
        Implementation of f3, the compute confidentiality key according
        to 3GPP 35.206 4.1

        Args:
            key (bytes): 128 bit subscriber key
            rand (bytes): 128 bit random challenge
            opc (bytes): 128 bit computed from OP and subscriber key
        Returns:
            ck, 128 bit confidentiality key
        """
        # Constants from 3GPP 35.206 4.1
        c3 = 15 * b'\x00' + b'\x02'  # some constant
        r3 = 4  # rotate by 4 bytes

        # TEMP = E_K(RAND XOR OP_C)
        # OUT3 = E_K(rotate(TEMP XOR OP_C, r3) XOR c3) XOR OP_C
        temp_x_opc = xor(cls.encrypt(key, xor(rand, opc)), opc)
        out3 = xor(cls.encrypt(key, xor(rotate(temp_x_opc, r3), c3)), opc)
        # ck = f3 = OUT3
        return out3

    @classmethod
    def f4(cls, key, rand, opc):
        """
        Implementation of f4, the integrity key according
        to 3GPP 35.206 4.1

        Args:
            key (bytes): 128 bit subscriber key
            rand (bytes): 128 bit random challenge
            opc (bytes): 128 bit computed from OP and subscriber key
        Returns:
            ik, 128 bit integrity key
        """
        # Constants from 3GPP 35.206 4.1
        c4 = 15 * b'\x00' + b'\x04'  # some constant
        r4 = 8  # rotate by 8 bytes

        # TEMP = E_K(RAND XOR OP_C)
        # OUT4 = E_K(rotate(TEMP XOR OP_C, r4) XOR c4) XOR OP_C
        temp_x_opc = xor(cls.encrypt(key, xor(rand, opc)), opc)
        out4 = xor(cls.encrypt(key, xor(rotate(temp_x_opc, r4), c4)), opc)
        # ik = f4 = OUT4
        return out4

    @classmethod
    def f5_star(cls, key, rand, opc):
        """
        Implementation of f5*, the anonymity key according
        to 3GPP 35.206 4.1

        Args:
            key (bytes): 128 bit subscriber key
            rand (bytes): 128 bit random challenge
            opc (bytes): 128 bit computed from OP and subscriber key
        Returns:
            ak, 48 bit anonymity key
        """
        # Constants from 3GPP 35.206 4.1
        c5 = 15 * b'\x00' + b'\x08'  # some constant
        r5 = 12  # rotate by 12 bytes

        # TEMP = E_K(RAND XOR OP_C)
        # OUT5 = E_K(rotate(TEMP XOR OP_C, r5 XOR c5) XOR OP_C
        temp_x_opc = xor(cls.encrypt(key, xor(rand, opc)), opc)
        out5 = xor(cls.encrypt(key, xor(rotate(temp_x_opc, r5), c5)), opc)
        # ak = f5* = OUT5[0] . OUT5[47]
        return out5[:6]

    @classmethod
    def generate_kasme(cls, ck, ik, plmn, sqn, ak):
        """
        KASME derivation function (S_2) according to 3GPP 33.401 Annex A.2.
        This function creates an input string to a key deriviation function.

        The input string to the KDF is composed of 2 input parameters P0, P1
        and their lengths L0, L1 a constant FC which identifies this algorithm.
                        S = FC || P0 || L0 || P1 || L1
        The FC = 0x10 and argument P0 is the 3 octets of the PLMN, and P1 is
        SQN XOR AK. The lengths are in bytes.

        The Kasme is computed by calling the key derivation function with S
        using key CK || IK

        Args:
            ck (bytes): 128 bit confidentiality key
            ik (bytes): 128 bit integrity key
            plmn (bytes): 24 bit network identifer
                Octet           Description
                  1      MCC digit 2 | MCC digit 1
                  2      MNC digit 3 | MCC digit 3
                  3      MNC digit 2 | MNC digit 1
            sqn (bytes): 48 bit sequence number
            ak (bytes): 48 bit anonymity key
        Returns:
            256 bit network base key
        """
        S = b'\x10' + plmn + b'\x00\x03' + xor(sqn, ak) + b'\x00\x06'
        return cls.KDF(ck + ik, S)

    @classmethod
    def generate_rand(cls):
        """
        Generate RAND for Milenage
        Returns:
            (bytes) 128 random bits
        """
        return bytearray.fromhex('{:032x}'.format(random.getrandbits(128)))

    @classmethod
    def generate_opc(cls, key, op):
        """
        Generate the OP_c according to 3GPP 35.205 8.2
        Args:
            key (bytes): 128 bit subscriber key
            op (bytes): 128 bit operator dependent value
        Returns:
            128 bit OP_c
        """
        opc = cls.encrypt(key, op)
        return xor(opc, op)

    @classmethod
    def generate_autn(cls, sqn, ak, mac_a, AMF=b'\x80\x00'):
        """
        Generate network authentication token as defined in 3GPP 25.205 7.2

        Args:
            sqn (bytes): 48 bit sequence number
            ak (bytes): 48 bit anonymity key
            mac_a (bytes): 64 bit network authentication code
            AMF (bytes): 16 bit authentication management field
        Returns:
            autn (bytes): 128 bit authentication token
        """
        CryptoLogger.debug("Attempting to xor(sqn, ak) where sqn is " + str(sqn) + " and AK is " + str(ak))
        xor_ak = xor(sqn, ak)
        CryptoLogger.debug("xor_ak output is " + str(xor_ak))
        return xor_ak + AMF + mac_a

    @classmethod
    def KDF(cls, key, buf):
        """
        3GPP Key Derivation Function defined in TS 33.220 to be hmac-sha256

        Args:
            key (bytes): 128 bit secret key
            buf (bytes): the buffer to compute the key from
        Returns:
            258 bit key
        """
        return hmac.new(key, buf, 'sha256').digest()

    @classmethod
    def encrypt(cls, k, buf, IV=16 * b'\x00'):
        """
        Rijndael (AES-128) cipher function used by Milenage

        Args:
            k (bytes): 128 bit encryption key
            buf (bytes): 128 bit buffer to encrypt
            IV (bytes): 128 bit initialization vector
        Returns:
            encrypted output
        """
        aes_cipher = AES.new(k, AES.MODE_CBC, IV)
        return aes_cipher.encrypt(buf)


def xor(s1, s2):
    """
    Exclusive-Or of two byte arrays

    Args:
        s1 (bytes): first set of bytes
        s2 (bytes): second set of bytes
    Returns:
        (bytes) s1 ^ s2
    Raises:
        ValueError if s1 and s2 lengths don't match
    """
    if len(s1) != len(s2):
        CryptoLogger.error("XOR Error - S1 and S2 don't match - Probably that space issue")
        #raise ValueError('Input not equal length, s1 is %d bytes and s2 is  %d bytes' % (len(s1), len(s2)))
    return bytes(a ^ b for a, b in zip(s1, s2))


def rotate(input_s, bytes_):
    """
    Rotate a string by a number of bytes

    Args:
        input_s (bytes): the input string
        bytes_ (int): the number of bytes to rotate by
    Returns:
        (bytes) s1 rotated by n bytes
    """
    return bytes(input_s[(i + bytes_) % len(input_s)] for i in range(len(
        input_s)))
