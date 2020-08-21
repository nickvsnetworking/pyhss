from milenage import Milenage
import binascii
import base64
import logging

def generate_eutran_vector(key, op, amf, sqn, plmn):
    logging.debug("Generting EUTRAN Vectors")
    key = key.encode('utf-8')
    logging.debug("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    op = op.encode('utf-8')
    logging.debug("Input OP:  " + str(op))
    op = binascii.unhexlify(op)
    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    logging.debug("Input AMF: " + str(amf))
    sqn = int(sqn)

    plmn = plmn.encode('utf-8')
    plmn = binascii.unhexlify(plmn)
    #plmn = b'\x05\xf5\x39'      #505 93
    #plmn = b'\x12\xf4\x10'      #214 01
    #print("PLMN: " )
    logging.debug(plmn)
    #Derrive OPc
    op_c = Milenage.generate_opc(key, op)

    logging.debug("Output OPc: " + str(binascii.hexlify(op_c).decode('utf-8')))

    crypto = Milenage(amf)

    (rand, xres, autn, kasme) = crypto.generate_eutran_vector(key, op_c, sqn, plmn)

    rand = binascii.hexlify(rand).decode('utf-8')

    logging.debug("output rand: " + str(rand))
    xres = binascii.hexlify(xres).decode('utf-8')
    logging.debug("output xres: " + str(xres))
    autn = binascii.hexlify(autn).decode('utf-8')
    logging.debug("output autn: " + str(autn))
    kasme = binascii.hexlify(kasme).decode('utf-8')
    logging.debug("output kasme: " + str(kasme))

    return (rand, xres, autn, kasme)
 

def generate_maa_vector(key, op, amf, sqn, plmn):
    logging.debug("Generting Multimedia Authentication Vector")
    key = key.encode('utf-8')
    #print("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    op = op.encode('utf-8')
    #print("Input OP:  " + str(op))
    op = binascii.unhexlify(op)
    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    #print("Input AMF: " + str(amf))
    sqn = int(sqn)

    plmn = plmn.encode('utf-8')
    plmn = binascii.unhexlify(plmn)
    #plmn = b'\x05\xf5\x39'      #505 93
    #plmn = b'\x12\xf4\x10'      #214 01
    #print("PLMN: " )
    #print(plmn)
    #Derrive OPc
    op_c = Milenage.generate_opc(key, op)

    #print("Output OPc: " + str(binascii.hexlify(op_c).decode('utf-8')))

    crypto = Milenage(amf)

    (rand, xres, autn, ck, ik) = crypto.generate_maa_vector(key, op_c, sqn, plmn)

    #rand = binascii.hexlify(rand).decode('utf-8')
    #print("output rand: " + str(rand))
    #print("rand type is : " + str(type(rand)))
    #xres = binascii.hexlify(xres).decode('utf-8')
    #print("output xres: " + str(xres))
    #autn = binascii.hexlify(autn).decode('utf-8')
    #print("output autn: " + str(autn))
    #ck = binascii.hexlify(ck).decode('utf-8')
    #ik = binascii.hexlify(ik).decode('utf-8')

    SIP_Authenticate = rand + autn
    #SIP_Authenticate = base64.b64encode(SIP_Authenticate.encode("utf-8"))

    return (SIP_Authenticate, xres, ck, ik)


def generate_resync_s6a(key, op, auts, rand):
    logging.debug("Generating correct SQN value from AUTS")

    key = key.encode('utf-8')
    #print("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    
    op = op.encode('utf-8')
    #print("Input OP:  " + str(op))
    op = binascii.unhexlify(op)

    auts = auts.encode('utf-8')
    #print("Input AUTS: " + str(auts))
    auts = binascii.unhexlify(auts)

    #Derrive OPc
    op_c = Milenage.generate_opc(key, op)
    crypto = Milenage(b'\x80\x00')

    #print("Output OPc: " + str(binascii.hexlify(op_c).decode('utf-8')))

    #Generate Resync
    sqn_ms_int, mac_s = crypto.generate_resync(auts, key, op_c, rand)
    logging.debug("SQN should be: " + str(sqn_ms_int))
    return(sqn_ms_int, mac_s)



