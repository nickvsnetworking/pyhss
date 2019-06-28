from milenage import Milenage
import binascii

##Generate EUTRAN Authentication Vector
key = b'AC71EC5E1371AB89D6E2A427B6D7E9AD'
key = binascii.unhexlify(key)
sqn = 3660
op = b'BA10AB971166F9B28B8B73AE5DF1BACA'
op = binascii.unhexlify(op)
amf = binascii.unhexlify(b'9999')
plmn = b'\x05\xf5\x39'      #505 93
op_c = Milenage.generate_opc(key, op)

crypto = Milenage(amf)

(rand_, xres_, autn_, kasme_) = crypto.generate_eutran_vector(key, op_c, sqn, plmn)

print("rand: " + binascii.hexlify(rand_).decode('utf-8'))
print("xres: " + binascii.hexlify(xres_).decode('utf-8'))
print("autn: " + binascii.hexlify(autn_).decode('utf-8'))
print("kasme: " + binascii.hexlify(kasme_).decode('utf-8'))


