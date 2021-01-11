from milenage import Milenage
import binascii
import base64
import logging


def generate_eutran_vector(key, op_c, amf, sqn, plmn):
    logging.debug("Generting EUTRAN Vectors")

    key = key.encode('utf-8')
    logging.debug("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    
    logging.debug("Input OPc is type " + str(type(op_c)) + " and value: " )
    logging.debug(op_c)
    op_c = op_c.encode('utf-8')
    logging.debug("Input OPc:  " + str(op_c))
    op_c = binascii.unhexlify(op_c)
    
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
 

def generate_maa_vector(key, op_c, amf, sqn, plmn):
    logging.debug("Generting Multimedia Authentication Vector")
    key = key.encode('utf-8')
    logging.debug("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    op_c = op_c.encode('utf-8')
    logging.debug("Input OPc:  " + str(op_c))
    op_c = binascii.unhexlify(op_c)
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
    #print(plmn)


    #print("Output OPc: " + str(binascii.hexlify(op_c).decode('utf-8')))

    crypto_obj = Milenage(amf)

    (rand, xres, autn, ck, ik) = crypto_obj.generate_maa_vector(key, op_c, sqn, plmn)

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


def generate_resync_s6a(key, op_c, amf, auts, rand):
    logging.debug("Generating correct SQN value from AUTS")

    key = key.encode('utf-8')
    logging.debug("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    
    op_c = op_c.encode('utf-8')
    op_c = binascii.unhexlify(op_c)

    auts = auts.encode('utf-8')
    logging.debug("Input AUTS: " + str(auts))
    auts = binascii.unhexlify(auts)

    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    logging.debug("Input AMF: " + str(amf))

    #print("Output OPc: " + str(binascii.hexlify(op_c).decode('utf-8')))

    #Generate Resync
    crypto_obj = Milenage(amf)
    sqn_ms_int, mac_s = crypto_obj.generate_resync(auts, key, op_c, rand)
    logging.debug("SQN should be: " + str(sqn_ms_int))
    return(sqn_ms_int, mac_s)

def generate_opc(key, op):
    #Generating OPc key from OP & K
    logging.debug("Generating OPc key from OP & K")
    key = key.encode('utf-8')
    key = binascii.unhexlify(key)
    op = op.encode('utf-8')
    op = binascii.unhexlify(op)
    opc = Milenage.generate_opc(key, op)
    return opc

