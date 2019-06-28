from milenage import Milenage
import binascii
import sys


##Derive OPc from OP
# Inputs
k = b'\x46\x5b\x5c\xe8\xb1\x99\xb4\x9f\xaa\x5f\x0a\x2e\xe2\x38\xa6\xbc'
op = b'\xcd\xc2\x02\xd5\x12> \xf6+mgj\xc7,\xb3\x18'
sqn = b'\xff\x9b\xb4\xd0\xb6\x07'
amf = b'\xb9\xb9'



# Outputs
opc = b'\xcdc\xcbq\x95J\x9fNH\xa5\x99N7\xa0+\xaf'
mac_a = b'\x4a\x9f\xfa\xc3\x54\xdf\xaf\xb3'
mac_s = b'\x01\xcf\xaf\x9e\xc4\xe8\x71\xe9'


#print(binascii.b2a_hex(opc_gen))



##Generate EUTRAN Authentication Vector
key = b'\x8b\xafG?/\x8f\xd0\x94\x87\xcc\xcb\xd7\t|hb'
sqn = 7351
op = 16 * b'\x11'
amf = b'\x80\x00'
plmn = b'\x02\xf8\x59'

op_c = b"\x8e'\xb6\xaf\x0ei.u\x0f2fz;\x14`]"
xres = b'\x2d\xaf\x87\x3d\x73\xf3\x10\xc6'
autn = b'o\xbf\xa3\x80\x1fW\x80\x00{\xdeY\x88n\x96\xe4\xfe'
kasme = (b'\x87H\xc1\xc0\xa2\x82o\xa4\x05\xb1\xe2~\xa1\x04CJ\xe5V\xc7e'
         b'\xe8\xf0a\xeb\xdb\x8a\xe2\x86\xc4F\x16\xc2')

crypto = Milenage(amf)
#print(crypto.generate_opc(key, op), op_c)




(rand_, xres_, autn_, kasme_) = crypto.generate_eutran_vector(key, op_c, sqn, plmn)

print("rand: " + binascii.hexlify(rand_).decode('utf-8'))
print("xres: " + binascii.hexlify(xres_).decode('utf-8'))
print("autn: " + binascii.hexlify(autn_).decode('utf-8'))
print("kasme: " + binascii.hexlify(kasme_).decode('utf-8'))

sys.exit()

#This all works.
#The answer as to why their keys are 16 bits long and ours are 32 is something to do with the encoding
#Check the NMS Web UI source code, how Magma stores it in the database is a big clue.
#Search "auth_opc" in https://github.com/facebookincubator/magma/blob/daa17c9c5d56c4ebc391e233696cf66b2f8acb52/nms/fbcnms-projects/magmalte/app/components/AddEditSubscriberDialog.js
#Line 96 (js)  is base64ToHex(editingSubscriber.lte.auth_opc)

#Real values
key = b'AC71EC5E1371AB89D6E2A427B6D7E9AD'
key = binascii.unhexlify(key)
op = b'BA10AB971166F9B28B8B73AE5DF1BACA'
op = binascii.unhexlify(op)
#9999                                AMF
#RAND 322708B8 5C7F31FC 0012F120 44EDBFDE
sqn = 3660
#XRES = dba298fe58effb09

print("Derrived OPc is:")
op_c = Milenage.generate_opc(key, op)
print(op_c)


(rand_, xres_, autn_, kasme_) = crypto.generate_eutran_vector(key, op_c, sqn, plmn)
print("Rand: " )

print(xres_)
print(autn_)
print(kasme_)
#AUTN = 37f6c414c0b799994a4fac34fb93bd42
#KASME = b5805bcaabe35aafebe1cc6eb53341b96128d1fd6e555a8cc343214233dcfbb0
