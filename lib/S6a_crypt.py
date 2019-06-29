from milenage import Milenage
import binascii

def generate_eutran_vector(key, op, amf, sqn):
    key = key.encode('utf-8')
    print(key)
    key = binascii.unhexlify(key)
    op = op.encode('utf-8')
    print(op)
    op = binascii.unhexlify(op)
    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    print(amf)
    sqn = int(sqn)
    print(sqn)
    plmn = b'\x05\xf5\x39'      #505 93
    #Derrive OPc
    op_c = Milenage.generate_opc(key, op)

    crypto = Milenage(amf)

    (rand, xres, autn, kasme) = crypto.generate_eutran_vector(key, op_c, sqn, plmn)

    rand = binascii.hexlify(rand).decode('utf-8')
    print("rand: " + str(rand))
    xres = binascii.hexlify(xres).decode('utf-8')
    print("xres: " + str(xres))
    autn = binascii.hexlify(autn).decode('utf-8')
    print("autn: " + str(autn))
    kasme = binascii.hexlify(kasme).decode('utf-8')
    print("kasme: " + str(kasme))

    return (rand, xres, autn, kasme)
 
