from milenage import Milenage
import binascii
import base64
import argparse

# Instantiate the parser
parser = argparse.ArgumentParser(description='LTE Authentication Vector Generator Tool')

#Incoming RTP Parameters
parser.add_argument('--k', type=str, required=True, help='K Key')
parser.add_argument('--op', type=str, required=False, help='OP Key')
parser.add_argument('--opc', type=str, required=False, help='OPc Key')
args = parser.parse_args()
key = str(args.k)
amf = 8000
sqn = 1
plmn = '37f800'
print(args)
if args.op is not None:
    op = str(args.op)
    print("Generating OPc key from OP & K")
    key = key.encode('utf-8')
    key = binascii.unhexlify(key)
    op = op.encode('utf-8')
    op = binascii.unhexlify(op)
    opc = Milenage.generate_opc(key, op)
    #convert back to string
    opc = binascii.hexlify(opc)
    op_c = opc.decode("utf-8")
    key = str(args.k)
else:
    print("Using OPc Provided")
    op_c = str(args.opc)

print("Generating Multimedia Authentication Vector")

#Convert to Bytes
key = key.encode('utf-8')

#Print Bytes
print("Input K:    " + str(key))
key = binascii.unhexlify(key)

op_c = op_c.encode('utf-8')

print("Input OPc:  " + str(op_c))
op_c = binascii.unhexlify(op_c)

amf = str(amf)
amf = amf.encode('utf-8')
amf = binascii.unhexlify(amf)
print("Input AMF:  " + str(amf))

sqn = int(sqn)
print("Input SQN:  " + str(sqn))

plmn = plmn.encode('utf-8')
plmn = binascii.unhexlify(plmn)
print("Input PLMN: " + str(plmn))


crypto_obj = Milenage(amf)

(rand, xres, autn, ck, ik) = crypto_obj.generate_maa_vector(key, op_c, sqn, plmn)

rand = binascii.hexlify(rand).decode('utf-8')
print("output rand: " + str(rand))
xres = binascii.hexlify(xres).decode('utf-8')
print("output xres: " + str(xres))
autn = binascii.hexlify(autn).decode('utf-8')
print("output autn: " + str(autn))
ck = binascii.hexlify(ck).decode('utf-8')
ik = binascii.hexlify(ik).decode('utf-8')

SIP_Authenticate = rand + autn
#SIP_Authenticate = base64.b64encode(SIP_Authenticate.encode("utf-8"))

print("SIP_Authenticate: " + str(SIP_Authenticate))
print("xres: " + xres)
print("CK: " + str(ck) + " ik: " + str(ik))
