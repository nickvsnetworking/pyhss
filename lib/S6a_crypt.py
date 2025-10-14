from comp128.comp128v1 import Comp128v1
from comp128.comp128v23 import Comp128v23
from milenage import Milenage
import binascii
import logging
import os
import sys
sys.path.append(os.path.realpath('../'))
import yaml

try:
    with open("../config.yaml", 'r') as stream:
        config = (yaml.safe_load(stream))
except:
    with open("config.yaml", 'r') as stream:
        config = (yaml.safe_load(stream))

# logtool = logtool.LogTool()
# logtool.setup_logger('CryptoLogger', yaml_config['logging']['logfiles']['database_logging_file'], level=yaml_config['logging']['level'])
CryptoLogger = logging.getLogger('CryptoLogger')

CryptoLogger.info("Initialised Diameter Logger, importing database")

#The EUTRAN Authentication Vector generator is based on the one used in [Facebook Magma](https://github.com/facebookincubator/magma), which in turn is based off [OAI-CN](https://github.com/OPENAIRINTERFACE/openair-cn).

def generate_eutran_vector(key, op_c, amf, sqn, plmn):
    CryptoLogger.debug("Generating EUTRAN Vectors")

    key = key.encode('utf-8')
    CryptoLogger.debug("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    
    op_c = op_c.encode('utf-8')
    CryptoLogger.debug("Input OPc:  " + str(op_c))
    op_c = binascii.unhexlify(op_c)
    
    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    CryptoLogger.debug("Input AMF: " + str(amf))
    
    sqn = int(sqn)
    CryptoLogger.debug("Input SQN: " + str(sqn))

    plmn = plmn.encode('utf-8')
    plmn = binascii.unhexlify(plmn)
    CryptoLogger.debug("Input PLMN: " + str(plmn))
    


    crypto = Milenage(amf)

    CryptoLogger.debug("Instantiated crypto object")
    CryptoLogger.debug("Running crypto.generate_eutran_vector")
    (rand, xres, autn, kasme) = crypto.generate_eutran_vector(key, op_c, sqn, plmn)
    CryptoLogger.debug("Successfully ran crypto.generate_eutran_vector")
    rand = binascii.hexlify(rand).decode('utf-8')

    CryptoLogger.debug("output rand: " + str(rand))
    xres = binascii.hexlify(xres).decode('utf-8')
    CryptoLogger.debug("output xres: " + str(xres))
    autn = binascii.hexlify(autn).decode('utf-8')
    CryptoLogger.debug("output autn: " + str(autn))
    kasme = binascii.hexlify(kasme).decode('utf-8')
    CryptoLogger.debug("output kasme: " + str(kasme))
    CryptoLogger.debug("Generated EUTRAN vectors")
    CryptoLogger.debug("Generated  RAND: " + str(rand))
    CryptoLogger.debug("Generated  XRES: " + str(xres))
    CryptoLogger.debug("Generated  AUTN: " + str(autn))
    CryptoLogger.debug("Generated KASME: " + str(kasme))
    CryptoLogger.debug("Successfully an S6a_crypt.generate_eutran_vector")
    return (rand, xres, autn, kasme)
 
def generate_maa_vector(key, op_c, amf, sqn, plmn):
    CryptoLogger.debug("Generating Multimedia Authentication Vector")
    key = key.encode('utf-8')
    CryptoLogger.debug("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    
    op_c = op_c.encode('utf-8')
    CryptoLogger.debug("Input OPc:  " + str(op_c))
    op_c = binascii.unhexlify(op_c)
    
    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    CryptoLogger.debug("Input AMF: " + str(amf))
    
    sqn = int(sqn)
    CryptoLogger.debug("Input SQN: " + str(sqn))

    plmn = plmn.encode('utf-8')
    plmn = binascii.unhexlify(plmn)
    CryptoLogger.debug("Input PLMN: " + str(plmn))
    

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
    # print("SIP_Authenticate: " + str(SIP_Authenticate))
    # print("xres: " + str(xres))
    # print("ck: " + str(ck))
    # print("ik: " + str(ik))
    return (rand, autn, xres, ck, ik)


def generate_2g3g_vector(key, op_c, amf, sqn, algo):
    CryptoLogger.debug("Generating 2G/3G Authentication Vector")
    key = key.encode('utf-8')
    CryptoLogger.debug("Input K:  " + str(key))
    key = binascii.unhexlify(key)

    op_c = op_c.encode('utf-8')
    CryptoLogger.debug("Input OPc:  " + str(op_c))
    op_c = binascii.unhexlify(op_c)

    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    CryptoLogger.debug("Input AMF: " + str(amf))

    sqn = int(sqn)
    CryptoLogger.debug("Input SQN: " + str(sqn))

    kc = None
    sres = None
    rand = Milenage.generate_rand()

    if algo == 1:
        crypto_obj = Comp128v1()
        sres, kc = crypto_obj.comp128v1(bytearray(key), rand)
    elif algo == 2:
        crypto_obj = Comp128v23()
        sres, kc = crypto_obj.comp128v2(bytearray(key), rand)
    elif algo == 3:
        crypto_obj = Comp128v23()
        sres, kc = crypto_obj.comp128v3(bytearray(key), rand)

    # Case: SIM only supports 2G Auth
    if op_c == b'':
        return dict(rand=rand, sres=sres, kc=kc)

    crypto_obj = Milenage(amf)
    (res, milenage_sres, autn, ck, ik, milenage_kc) = crypto_obj.generate_2g3g_vector(key, op_c, rand, sqn)

    # Case: SIM supports both 2G and 3G Auth -> leave kc and sres as is
    # Case: SIM only supports 3G Auth -> overwrite kc and sres with milenage values
    if sres is None or kc is None:
        sres = milenage_sres
        kc = milenage_kc

    return dict(rand=rand, autn=autn, res=res, sres=sres, ck=ck, ik=ik, kc=kc)

def generate_eap_aka_vector(key, op_c, amf, sqn, plmn):
    CryptoLogger.debug("Generating EAP-AKA Vector")
    key = key.encode('utf-8')
    CryptoLogger.debug("Input K:  " + str(key))
    key = binascii.unhexlify(key)
    
    op_c = op_c.encode('utf-8')
    CryptoLogger.debug("Input OPc:  " + str(op_c))
    op_c = binascii.unhexlify(op_c)
    
    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    CryptoLogger.debug("Input AMF: " + str(amf))
    
    sqn = int(sqn)
    CryptoLogger.debug("Input SQN: " + str(sqn))

    plmn = plmn.encode('utf-8')
    plmn = binascii.unhexlify(plmn)
    CryptoLogger.debug("Input PLMN: " + str(plmn))
    
    crypto_obj = Milenage(amf)

    return crypto_obj.generate_eap_aka_vector(key, op_c, sqn, plmn)

def generate_resync_s6a(key, op_c, amf, auts, rand):
    CryptoLogger.debug("Generating correct SQN value from AUTS")

    CryptoLogger.debug("\tInput RAND: " + str(rand))

    key = key.encode('utf-8')
    CryptoLogger.debug("\tInput K:  " + str(key))
    key = binascii.unhexlify(key)
    
    op_c = op_c.encode('utf-8')
    CryptoLogger.debug("\tInput OPc:  " + str(op_c))
    op_c = binascii.unhexlify(op_c)

    auts = auts.encode('utf-8')
    CryptoLogger.debug("\tInput AUTS: " + str(auts))
    auts = binascii.unhexlify(auts)

    amf = str(amf)
    amf = amf.encode('utf-8')
    amf = binascii.unhexlify(amf)
    CryptoLogger.debug("\tInput AMF: " + str(amf))

    #Generate Resync
    crypto_obj = Milenage(amf)
    sqn_ms_int, mac_s = crypto_obj.generate_resync(auts, key, op_c, rand)
    CryptoLogger.debug("SQN should be: " + str(sqn_ms_int))
    CryptoLogger.debug("Successfully generated resync")
    CryptoLogger.debug("Generated  sqn_ms_int: " + str(sqn_ms_int))
    CryptoLogger.debug("Generated  mac_s: " + str(mac_s))    
    return(sqn_ms_int, mac_s)

def generate_opc(key, op):
    #Generating OPc key from OP & K
    CryptoLogger.debug("Generating OPc key from OP & K")
    key = key.encode('utf-8')
    key = binascii.unhexlify(key)
    op = op.encode('utf-8')
    op = binascii.unhexlify(op)
    opc = Milenage.generate_opc(key, op)
    #convert back to string
    opc = binascii.hexlify(opc)
    opc = opc.decode("utf-8")
    return opc

