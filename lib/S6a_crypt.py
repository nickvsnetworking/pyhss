from milenage import Milenage
import binascii

def generate_eutran_vector(key, op, amf, sqn, plmn):
    print("Generting EUTRAN Vectors")
    key = key.encode('utf-8')
    print("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    op = op.encode('utf-8')
    print("Input OP:  " + str(op))
    op = binascii.unhexlify(op)
    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    print("Input AMF: " + str(amf))
    sqn = int(sqn)

    plmn = plmn.encode('utf-8')
    plmn = binascii.unhexlify(plmn)
    #plmn = b'\x05\xf5\x39'      #505 93
    #plmn = b'\x12\xf4\x10'      #214 01
    print("PLMN: " )
    print(plmn)
    #Derrive OPc
    op_c = Milenage.generate_opc(key, op)

    print("Output OPc: " + str(binascii.hexlify(op_c).decode('utf-8')))

    crypto = Milenage(amf)

    (rand, xres, autn, kasme) = crypto.generate_eutran_vector(key, op_c, sqn, plmn)

    rand = binascii.hexlify(rand).decode('utf-8')

    print("output rand: " + str(rand))
    xres = binascii.hexlify(xres).decode('utf-8')
    print("output xres: " + str(xres))
    autn = binascii.hexlify(autn).decode('utf-8')
    print("output autn: " + str(autn))
    kasme = binascii.hexlify(kasme).decode('utf-8')
    print("output kasme: " + str(kasme))

    return (rand, xres, autn, kasme)
 

def generate_resync_s6a(key, op, auts, rand):
    print("\nGenerating correct SQN value from AUTS")

    key = key.encode('utf-8')
    print("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    op = op.encode('utf-8')
    print("Input OP:  " + str(op))
    op = binascii.unhexlify(op)

    auts = auts.encode('utf-8')
    #auts = binascii.unhexlify(auts)

    #Derrive OPc
    op_c = Milenage.generate_opc(key, op)
    crypto = Milenage(b'\x80\x00')

    print("Output OPc: " + str(binascii.hexlify(op_c).decode('utf-8')))
    print(type(op_c))
    print(len(op_c))

    print("here we go...")
    #Generate Resync
    sqn_ms_int, mac_s = crypto.generate_resync(auts, key, op_c, rand)
    print("SQN should be: " + str(sqn_ms_int))
    print(mac_s)
    return(sqn_ms_int, mac_s)



##auts = 'ba2b497c45cdce3e38965f6ec76821577d92b1f29b753c492215b8706663'
##op = 'BA10AB971166F9B28B8B73AE5DF1BACA'
##rand = '1764d7bc135c8f72cbb039bd58b66bbd'
##key = '465B5CE8B199B49FAA5F0A2EE238A6BC'
##amf = '8000'
##sqn = '2480'
##rand, xres, autn, kasme = generate_eutran_vector(key, op, amf, sqn)
##print("Vector Computed RAND  : " + str(rand))
##print("Vector Computed XRES  : " + str(xres))
##print("Vector Computed AUTN  : " + str(autn))
##print("Vector Computed KASME : " + str(kasme))
##
##
##print(generate_resync_s6a(key, op, auts, rand))
