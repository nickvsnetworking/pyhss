import sys
from sqlalchemy import Column, Integer, String, MetaData, Table, Boolean, ForeignKey, select, UniqueConstraint, DateTime
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.orm import sessionmaker
import json
import datetime

import os
import sys
sys.path.append(os.path.realpath('lib'))

import yaml
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

#engine = create_engine('sqlite:///sales.db', echo = True)
db_string = 'mysql://' + str(yaml_config['database']['username']) + ':' + str(yaml_config['database']['password']) + '@' + str(yaml_config['database']['server']) + '/' + str(yaml_config['database']['database'])
print(db_string)
engine = create_engine(db_string, echo = True)
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

import logging
import logtool
logtool = logtool.LogTool()
logtool.setup_logger('DBLogger', yaml_config['logging']['logfiles']['database_logging_file'], level=yaml_config['logging']['level'])
DBLogger = logging.getLogger('DBLogger')
import pprint
DBLogger.info("DB Log Initialised.")
from logtool import *

import os
from construct import Default
sys.path.append(os.path.realpath('lib'))
import S6a_crypt

# Create database if it does not exist.
if not database_exists(engine.url):
    create_database(engine.url)
else:
    # Connect the database if exists.
    engine.connect()

class APN(Base):
    __tablename__ = 'apn'
    apn_id = Column(Integer, primary_key=True)
    apn = Column(String(50), nullable=False)
    pgw_address = Column(String(50))
    sgw_address = Column(String(50))
    charging_characteristics = Column( String(4), default='0800')
    apn_ambr_dl = Column(Integer, nullable=False)
    apn_ambr_ul = Column(Integer, nullable=False)
    qci = Column(Integer, default=9)
    arp_priority = Column(Integer, default=4)
    arp_preemption_capability = Column(Boolean, default=False)
    arp_preemption_vulnerability = Column(Boolean, default=True)

class Serving_APN(Base):
    __tablename__ = 'serving_apn'
    serving_apn_id = Column(Integer, primary_key=True)
    subscriber_id = Column(Integer, ForeignKey('subscriber.subscriber_id'))
    apn = Column(Integer, ForeignKey('apn.apn_id'))
    serving_pgw = Column(String(50))
    serving_pgw_timestamp = Column(DateTime)


class AUC(Base):
    __tablename__ = 'auc'
    auc_id = Column(Integer, primary_key = True)
    ki = Column(String(32))
    opc = Column(String(32))
    amf = Column(String(4))
    sqn = Column(Integer)


class SUBSCRIBER(Base):
    __tablename__ = 'subscriber'
    subscriber_id = Column(Integer, primary_key = True)
    imsi = Column(String(18), unique=True)
    enabled = Column(Boolean, default=1)
    auc_id = Column(Integer, ForeignKey('auc.auc_id'))
    default_apn = Column(Integer, ForeignKey('apn.apn_id'))
    apn_list = Column(String(18))
    msisdn = Column(String(18))
    ue_ambr_dl = Column(Integer, default=999999)
    ue_ambr_ul = Column(Integer, default=999999)
    nam = Column(Integer, default=0)
    subscribed_rau_tau_timer = Column(Integer, default=300)
    serving_mme = Column(String(50))
    serving_mme_timestamp = Column(DateTime)

class IMS_SUBSCRIBER(Base):
    __tablename__ = 'ims_subscriber'
    ims_subscriber_id = Column(Integer, primary_key = True)
    msisdn = Column(String(18), unique=True)
    msisdn_list = Column(String(1200))
    imsi = Column(String(18), unique=False)
    ifc_path = Column(String(18))
    sh_profile = Column(String(12000))
    scscf = Column(String(50))
    scscf_timestamp = Column(DateTime)


Base.metadata.create_all(engine)
Session = sessionmaker(bind = engine)
session = Session()

def GetObj(obj_type, obj_id):
    print("Called GetObj for type " + str(obj_type) + " with id " + str(obj_id))
    result = session.query(obj_type).get(obj_id)
    result = result.__dict__
    result.pop('_sa_instance_state')
    for keys in result:
        if type(result[keys]) == DateTime:
            result[keys] = str(result[keys])
    return result

def UpdateObj(obj_type, json_data, obj_id):
    print("Called UpdateObj() for type " + str(obj_type) + " id " + str(obj_id) + " with JSON data: " + str(json_data))
    obj_type_str = str(obj_type.__table__.name).upper()
    print("obj_type_str is " + str(obj_type_str))
    filter_input = eval(obj_type_str + "." + obj_type_str.lower() + "_id==obj_id")
    sessionquery = session.query(obj_type).filter(filter_input)
    print("got result: " + str(sessionquery.__dict__))
    sessionquery.update(json_data, synchronize_session = False)
    session.commit()
    return GetObj(obj_type, obj_id)

def DeleteObj(obj_type, obj_id):
    print("Called DeleteObj for type " + str(obj_type) + " with id " + str(obj_id))
    res = session.query(obj_type).get(obj_id)
    session.delete(res)
    session.commit()
    return {"Result":"OK"}

def CreateObj(obj_type, json_data):
    newObj = obj_type(**json_data)
    session.add(newObj)
    session.commit()
    session.refresh(newObj)
    result = newObj.__dict__
    result.pop('_sa_instance_state')
    return result

def Generate_JSON_Model_for_Flask(obj_type):
    from alchemyjsonschema import SchemaFactory
    from alchemyjsonschema import NoForeignKeyWalker
    import pprint as pp
    factory = SchemaFactory(NoForeignKeyWalker)
    dictty = dict(factory(obj_type))
    dictty['properties'] = dict(dictty['properties'])

    #Set the ID Object to not required
    obj_type_str = str(dictty['title']).lower()
    dictty['required'].remove(obj_type_str + '_id')
   
    return dictty

def Get_IMS_Subscriber(**kwargs):
    #Get subscriber by IMSI or MSISDN
    if 'msisdn' in kwargs:
        print("Get_IMS_Subscriber for msisdn " + str(kwargs['msisdn']))
        try:
            result = session.query(SUBSCRIBER).filter_by(msisdn=str(kwargs['msisdn'])).one()
        except:
            raise ValueError("IMS Subscriber not Found")
    elif 'imsi' in kwargs:
        print("Get_IMS_Subscriber for imsi " + str(kwargs['imsi']))
        try:
            result = session.query(IMS_SUBSCRIBER).filter_by(imsi=str(kwargs['imsi'])).one()
        except:
            raise ValueError("IMS Subscriber not Found")
    print("Converting result to dict")
    result = result.__dict__
    try:
        result.pop('_sa_instance_state')
    except:
        pass
    print("Returning IMS Subscriber Data: " + str(result))
    return result

def Get_Subscriber(imsi):
    print("Get_Subscriber for IMSI " + str(imsi))
    try:
        result = session.query(SUBSCRIBER).filter_by(imsi=imsi).one()
    except:
        raise ValueError("Subscriber not Found")
    result = result.__dict__
    result.pop('_sa_instance_state')
    return result

def Get_Vectors_AuC(auc_id, action, **kwargs):
    print("Getting Vectors for auc_id " + str(auc_id) + " with action " + str(action))
    key_data = GetObj(AUC, auc_id)
    vector_dict = {}
    
    if action == "air":
        rand, xres, autn, kasme = S6a_crypt.generate_eutran_vector(key_data['ki'], key_data['opc'], key_data['amf'], key_data['sqn'], kwargs['plmn']) 
        vector_dict['rand'] = rand
        vector_dict['xres'] = xres
        vector_dict['autn'] = autn
        vector_dict['kasme'] = kasme

        #Incriment SQN
        Update_AuC(auc_id, sqn=key_data['sqn']+100)

        return vector_dict

    elif action == "air_resync":
        print("Resync SQN")
        sqn, mac_s = S6a_crypt.generate_resync_s6a(key_data['ki'], key_data['opc'], key_data['amf'], kwargs['auts'], kwargs['rand'])
        print("SQN from resync: " + str(sqn) + " SQN in DB is "  + str(key_data['sqn']) + "(Difference of " + str(int(sqn) - int(key_data['sqn'])) + ")")
        Update_AuC(auc_id, sqn=sqn+100)
        return
    
    elif action == "sip_auth":
        SIP_Authenticate, xres, ck, ik = S6a_crypt.generate_maa_vector(key_data['ki'], key_data['opc'], key_data['amf'], key_data['sqn'], kwargs['plmn'])
        vector_dict['SIP_Authenticate'] = SIP_Authenticate
        vector_dict['xres'] = xres
        vector_dict['ck'] = ck
        vector_dict['ik'] = ik
        Update_AuC(auc_id, sqn=key_data['sqn']+100)
        return vector_dict

def Get_APN(apn_id):
    print("Getting APN " + str(apn_id))
    try:
        result = session.query(APN).filter_by(apn_id=apn_id).one()
    except:
        raise ValueError("APN not Found")
    result = result.__dict__
    result.pop('_sa_instance_state')
    return result    

def Update_AuC(auc_id, sqn=1):
    print("Incrimenting SQN for sub " + str(auc_id))
    print(UpdateObj(AUC, {'sqn': sqn}, auc_id))
    return

def Update_Serving_MME(imsi, serving_mme):
    print("Updating Serving MME for sub " + str(imsi) + " to MME " + str(serving_mme))
    result = session.query(SUBSCRIBER).filter_by(imsi=imsi).one()
    if type(serving_mme) == str:
        print("Updating serving MME")
        result.serving_mme = serving_mme
        result.serving_mme_timestamp = datetime.datetime.now()
    else:
        #Clear values
        print("Clearing serving MME")
        result.serving_mme = None
        result.serving_mme_timestamp = None
    session.commit()
    return

def Update_Serving_CSCF(imsi, serving_cscf):
    print("Update_Serving_CSCF for sub " + str(imsi) + " to SCSCF " + str(serving_cscf))
    result = session.query(IMS_SUBSCRIBER).filter_by(imsi=imsi).one()
    if type(serving_cscf) == str:
        print("Updating serving CSCF")
        result.scscf = serving_cscf
        result.scscf_timestamp = datetime.datetime.now()
    else:
        #Clear values
        print("Clearing serving CSCF")
        result.scscf = None
        result.scscf_timestamp = None
    session.commit()
    return    

def Update_Location(imsi, apn, diameter_realm, diameter_peer, diameter_origin):
    return

def Get_IMSI_from_MSISDN(msisdn):
    return

if __name__ == "__main__":  

    import binascii,os
    apn2 = {'apn':'fadsgdsags', \
        'apn_ambr_dl' : 9999, 'apn_ambr_ul' : 9999, \
        'arp_priority': 1, 'arp_preemption_capability' : False, \
        'arp_preemption_vulnerability': True}
    newObj = CreateObj(APN, apn2)
    print(newObj)

    print(GetObj(APN, newObj['apn_id']))
    apn_id = newObj['apn_id']
    UpdatedObj = newObj
    UpdatedObj['apn'] = 'UpdatedInUnitTest'
    
    newObj = UpdateObj(APN, UpdatedObj, newObj['apn_id'])
    print(newObj)

    #Create AuC
    auc_json = {
    "ki": binascii.b2a_hex(os.urandom(16)).zfill(16),
    "opc": binascii.b2a_hex(os.urandom(16)).zfill(16),
    "amf": "9000",
    "sqn": 0
    }
    print(auc_json)
    newObj = CreateObj(AUC, auc_json)
    print(newObj)

    #Get AuC
    newObj = GetObj(AUC, newObj['auc_id'])
    auc_id = newObj['auc_id']
    print(newObj)

    #Update AuC
    newObj['sqn'] = newObj['sqn'] + 10
    newObj = UpdateObj(AUC, newObj, auc_id)

    #Generate Vectors
    Get_Vectors_AuC(auc_id, "air", plmn='12ff')
    print(Get_Vectors_AuC(auc_id, "sip_auth", plmn='12ff'))

    #New Subscriber
    subscriber_json = {
        "imsi": "001001000000006",
        "enabled": True,
        "msisdn": "12345678",
        "ue_ambr_dl": 999999,
        "ue_ambr_ul": 999999,
        "nam": 0,
        "subscribed_rau_tau_timer": 600,
        "auc_id" : auc_id,
        "default_apn" : apn_id,
        "apn_list" : apn_id
    }

    #Delete IMSI if already exists
    try:
        existing_sub_data = Get_Subscriber(subscriber_json['imsi'])
        DeleteObj(SUBSCRIBER, existing_sub_data['subscriber_id'])
    except:
        print("Did not find old sub to delete")

    print(subscriber_json)
    newObj = CreateObj(SUBSCRIBER, subscriber_json)
    print(newObj)
    subscriber_id = newObj['subscriber_id']

    #Get SUBSCRIBER
    newObj = GetObj(SUBSCRIBER, subscriber_id)
    print(newObj)

    #Update SUBSCRIBER
    newObj['ue_ambr_ul'] = 999995
    newObj = UpdateObj(SUBSCRIBER, newObj, subscriber_id)

    #Set MME Location for Subscriber
    Update_Serving_MME(newObj['imsi'], "Test123")
    #Clear MME Location for Subscriber    
    Update_Serving_MME(newObj['imsi'], None)

    #New IMS Subscriber
    ims_subscriber_json = {
        "msisdn": newObj['msisdn'], 
        "msisdn_list": newObj['msisdn'],
        "imsi": subscriber_json['imsi'],
        "ifc_path" : "default_ifc.xml",
        "sh_profile" : "default_sh_user_data.xml"
    }
    print(ims_subscriber_json)
    newObj = CreateObj(IMS_SUBSCRIBER, ims_subscriber_json)
    print(newObj)
    ims_subscriber_id = newObj['ims_subscriber_id']


    #Test Get Subscriber
    GetSubscriber_Result = Get_Subscriber(subscriber_json['imsi'])
    print(GetSubscriber_Result)

    #Test IMS Get Subscriber
    print("\n\n\n")
    print(Get_IMS_Subscriber(imsi='001001000000006'))
    print(Get_IMS_Subscriber(msisdn='12345678'))

    #Set SCSCF for Subscriber
    Update_Serving_CSCF(newObj['imsi'], "NickTestCSCF")
    #Clear MME Location for Subscriber    
    Update_Serving_CSCF(newObj['imsi'], None)

    #Test getting APNs
    GetAPN_Result = Get_APN(GetSubscriber_Result['default_apn'])
    print(GetAPN_Result)


    #Delete IMS Subscriber
    print(DeleteObj(IMS_SUBSCRIBER, ims_subscriber_id))
    #Delete Subscriber
    print(DeleteObj(SUBSCRIBER, subscriber_id))
    #Delete AuC
    print(DeleteObj(AUC, auc_id))
    #Delete APN
    print(DeleteObj(APN, apn_id))
