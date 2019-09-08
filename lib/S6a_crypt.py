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
 

def generate_resync(key, op, rand):

    sqn = 1383

    
    auts = key.encode('utf-8')
    op = op.encode('utf-8')
    op = binascii.unhexlify(op)
    rand = rand.encode('utf-8')
    rand = binascii.unhexlify(rand)
    amf = 8000
    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    crypto = Milenage(amf)

    #Derrive OPc
    op_c = Milenage.generate_opc(key, op)

    auts = crypto.generate_auts(key, op_c, rand, sqn)

    sqn_ms_int, mac_s = crypto.generate_resync(auts, key, op_c, rand)
    print(sqn_ms_int)
    print(mac_s)

#auts = '1764d7bc135c8f72cbb039bd58b66bbd46af726351ae673f149a4f618c54'
##op = 'BA10AB971166F9B28B8B73AE5DF1BACA'
##rand = '1764d7bc135c8f72cbb039bd58b66bbd46af726351ae673f149a4f618c54'
##key = '465B5CE8B199B49FAA5F0A2EE238A6BC'
##generate_resync(key, op, '5b88d18a6fa7523f40efb30457ac2c63')
