import sys
from sqlalchemy import Column, Integer, String, MetaData, Table, Boolean, ForeignKey, select, UniqueConstraint, DateTime, BigInteger
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.orm import sessionmaker
import json
import datetime
import re
import os
import sys
import binascii
sys.path.append(os.path.realpath('lib'))

import yaml
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

#engine = create_engine('sqlite:///sales.db', echo = True)
db_string = 'mysql://' + str(yaml_config['database']['username']) + ':' + str(yaml_config['database']['password']) + '@' + str(yaml_config['database']['server']) + '/' + str(yaml_config['database']['database'] + "?autocommit=true")
print(db_string)
engine = create_engine(db_string, echo = True, pool_recycle=5)
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
import requests
import threading

class APN(Base):
    __tablename__ = 'apn'
    apn_id = Column(Integer, primary_key=True, doc='Unique ID of APN')
    apn = Column(String(50), nullable=False, doc='Short name of the APN')
    ip_version = Column(Integer, default=0, doc="IP version used - 0: ipv4, 1: ipv6 2: ipv4+6 3: ipv4 or ipv6 [3GPP TS 29.272 7.3.62]")
    pgw_address = Column(String(50), doc='IP of the PGW')
    sgw_address = Column(String(50), doc='IP of the SGW')
    charging_characteristics = Column(String(4), default='0800', doc='For the encoding of this information element see 3GPP TS 32.298 [9]')
    apn_ambr_dl = Column(Integer, nullable=False, doc='Downlink Maximum Bit Rate for this APN')
    apn_ambr_ul = Column(Integer, nullable=False, doc='Uplink Maximum Bit Rate for this APN')
    qci = Column(Integer, default=9, doc='QoS Class Identifier')
    arp_priority = Column(Integer, default=4, doc='Allocation and Retention Policy - Bearer priority level (1-15)')
    arp_preemption_capability = Column(Boolean, default=False, doc='Allocation and Retention Policy - Capability to Preempt resources from other Subscribers')
    arp_preemption_vulnerability = Column(Boolean, default=True, doc='Allocation and Retention Policy - Vulnerability to have resources Preempted by other Subscribers')
    charging_rule_list = Column(String(18), doc='Comma separated list of predefined ChargingRules to be installed in CCA-I')

class SERVING_APN(Base):
    __tablename__ = 'serving_apn'
    serving_apn_id = Column(Integer, primary_key=True, doc='Unique ID of SERVING_APN')
    subscriber_id = Column(Integer, ForeignKey('subscriber.subscriber_id'), doc='subscriber_id of the served subscriber')
    apn = Column(Integer, ForeignKey('apn.apn_id'), doc='apn_id of the APN served')
    pcrf_session_id = Column(String(100), doc='Session ID from the PCRF')
    ue_ip = Column(String(100), doc='IP Address allocated to the UE')
    ip_version = Column(Integer, default=0, doc=APN.ip_version.doc)
    serving_pgw = Column(String(50), doc='PGW serving this subscriber')
    serving_pgw_timestamp = Column(DateTime, doc='Timestamp of attach to PGW')

class AUC(Base):
    __tablename__ = 'auc'
    auc_id = Column(Integer, primary_key = True, doc='Unique ID of AuC entry')
    ki = Column(String(32), doc='SIM Key - Authentication Key - Ki')
    opc = Column(String(32), doc='SIM Key - Network Operators key OPc')
    amf = Column(String(4), doc='Authentication Management Field')
    sqn = Column(BigInteger, doc='Authentication sequence number')

class SUBSCRIBER(Base):
    __tablename__ = 'subscriber'
    subscriber_id = Column(Integer, primary_key = True, doc='Unique ID of Subscriber entry')
    imsi = Column(String(18), unique=True, doc='International Mobile Subscriber Identity')
    enabled = Column(Boolean, default=1, doc='Subscriber enabled/disabled')
    auc_id = Column(Integer, ForeignKey('auc.auc_id'), doc='Reference to AuC ID defined with SIM Auth data', nullable=False)
    default_apn = Column(Integer, ForeignKey('apn.apn_id'), doc='APN ID to use for the default APN', nullable=False)
    apn_list = Column(String(64), doc='Comma separated list of allowed APNs', nullable=False)
    msisdn = Column(String(18), doc='Primary Phone number of Subscriber')
    ue_ambr_dl = Column(Integer, default=999999, doc='Downlink Aggregate Maximum Bit Rate')
    ue_ambr_ul = Column(Integer, default=999999, doc='Uplink Aggregate Maximum Bit Rate')
    nam = Column(Integer, default=0, doc='Network Access Mode [3GPP TS. 123 008 2.1.1.2]')
    subscribed_rau_tau_timer = Column(Integer, default=300, doc='Subscribed periodic TAU/RAU timer value in seconds')
    serving_mme = Column(String(50), doc='MME serving this subscriber')
    serving_mme_timestamp = Column(DateTime, doc='Timestamp of attach to MME')

class IMS_SUBSCRIBER(Base):
    __tablename__ = 'ims_subscriber'
    ims_subscriber_id = Column(Integer, primary_key = True, doc='Unique ID of IMS_Subscriber entry')
    msisdn = Column(String(18), unique=True, doc=SUBSCRIBER.msisdn.doc)
    msisdn_list = Column(String(1200), doc='Coma Separated list of additional MSISDNs for Subscriber')
    imsi = Column(String(18), unique=False, doc=SUBSCRIBER.imsi.doc)
    ifc_path = Column(String(18), doc='Path to template file for the Initial Filter Criteria')
    sh_profile = Column(String(12000), doc='Sh Subscriber Profile')
    scscf = Column(String(50), doc='Serving-CSCF serving this subscriber')
    scscf_timestamp = Column(DateTime, doc='Timestamp of attach to S-CSCF')

class CHARGING_RULE(Base):
    __tablename__ = 'charging_rule'
    charging_rule_id = Column(Integer, primary_key = True, doc='Unique ID of CHARGING_RULE entry')
    rule_name = Column(String(20), doc='Name of rule pushed to PGW (Short, no special chars)')
    
    qci = Column(Integer, default=9, doc=APN.qci.doc)
    arp_priority = Column(Integer, default=4, doc=APN.arp_priority.doc)
    arp_preemption_capability = Column(Boolean, default=False, doc=APN.arp_preemption_capability.doc)
    arp_preemption_vulnerability = Column(Boolean, default=True, doc=APN.arp_preemption_vulnerability.doc)    

    mbr_dl = Column(Integer, nullable=False, doc='Maximum Downlink Bitrate for traffic matching this rule')
    mbr_ul = Column(Integer, nullable=False, doc='Maximum Uplink Bitrate for traffic matching this rule')
    gbr_dl = Column(Integer, nullable=False, doc='Guaranteed Downlink Bitrate for traffic matching this rule')
    gbr_ul = Column(Integer, nullable=False, doc='Guaranteed Uplink Bitrate for traffic matching this rule')    
    tft_group_id = Column(Integer, doc='Will match any TFTs using this TFT Group to form the TFT list used in the Charging Rule')
    precedence = Column(Integer, doc='Precedence of this rule, allows rule to override or be overridden by a higher priority rule')
    rating_group = Column(Integer, doc='Rating Group in OCS / OFCS that traffic matching this rule will be charged under')

class TFT(Base):
    __tablename__ = 'tft'
    tft_id = Column(Integer, primary_key = True, doc='Unique ID of CHARGING_RULE entry')
    tft_group_id = Column(Integer, nullable=False, doc=CHARGING_RULE.tft_group_id.doc)
    tft_string = Column(String(100), nullable=False, doc='IPFilterRules as defined in [RFC 6733] taking the format: action dir proto from src to dst')
    direction = Column(Integer, nullable=False, doc='Traffic Direction: 0- Unspecified, 1 - Downlink, 2 - Uplink, 3 - Bidirectional')

class EIR(Base):
    __tablename__ = 'eir'
    eir_id = Column(Integer, primary_key = True, doc='Unique ID of EIR entry')
    imei = Column(String(60), doc='Exact IMEI or Regex to match IMEI (Depending on regex_mode value)')
    imsi = Column(String(60), doc='Exact IMSI or Regex to match IMSI (Depending on regex_mode value)')
    regex_mode = Column(Integer, default=1, doc='0 - Exact Match mode, 1 - Regex Mode')
    match_response_code = Column(Integer, doc='0 - Whitelist, 1 - Blacklist, 2 - Greylist')

class IMSI_IMEI_HISTORY(Base):
    __tablename__ = 'eir_history'
    imsi_imei_history_id = Column(Integer, primary_key = True, doc='Unique ID of IMSI_IMEI_HISTORY entry')
    imsi_imei = Column(String(60), unique=True, doc='Combined IMSI + IMEI value')
    match_response_code = Column(Integer, doc='Response code that was returned')
    imsi_imei_timestamp = Column(DateTime, doc='Timestamp of last match')

# Create database if it does not exist.
if not database_exists(engine.url):
    DBLogger.debug("Creating database")
    create_database(engine.url)
    Base.metadata.create_all(engine)
else:
    DBLogger.debug("Database already created")

def GeoRed_Push_Request(remote_hss, json_data):
    headers = {"Content-Type": "application/json"}
    DBLogger.debug("Pushing update to remote PyHSS " + str(remote_hss) + " with JSON body: " + str(json_data))
    try:
        r = requests.patch(str(remote_hss) + '/geored/', data=json.dumps(json_data), headers=headers)
        DBLogger.debug("Updated on " + str(remote_hss))
    except requests.exceptions.RequestException as E:  # This is the correct syntax
        DBLogger.error("Failed to push data to remote PyHSS instance at " + str(remote_hss))
        DBLogger.error(E)

def GeoRed_Push_Async(json_data):
    if yaml_config['geored']['enabled'] == True:
        for remote_hss in yaml_config['geored']['sync_endpoints']:
            GeoRed_Push_thread = threading.Thread(target=GeoRed_Push_Request, args=(remote_hss, json_data))
            GeoRed_Push_thread.start()

def Sanitize_Datetime(result):
    for keys in result:
        if "timestamp" in keys:
            if result[keys] == None:
                continue
            else:
                DBLogger.debug("Key " + str(keys) + " is type DateTime with value: " + str(result[keys]) + " - Formatting to String")
                result[keys] = str(result[keys])
    return result

def GetObj(obj_type, obj_id):
    DBLogger.debug("Called GetObj for type " + str(obj_type) + " with id " + str(obj_id))

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind = engine)
    session = Session()

    try:
        result = session.query(obj_type).get(obj_id)
    except Exception as E:
        DBLogger.error("Failed to query, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)    
    
    result = result.__dict__
    result.pop('_sa_instance_state')
    result = Sanitize_Datetime(result)
    session.close()
    return result

def GetAll(obj_type):
    DBLogger.debug("Called GetAll for type " + str(obj_type))

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind = engine)
    session = Session()
    final_result_list = []

    try:
        result = session.query(obj_type)
    except Exception as E:
        DBLogger.error("Failed to query, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)    
    
    for record in result:
        record = record.__dict__
        record.pop('_sa_instance_state')
        record = Sanitize_Datetime(record)
        final_result_list.append(record)

    session.close()
    return final_result_list

def UpdateObj(obj_type, json_data, obj_id):
    DBLogger.debug("Called UpdateObj() for type " + str(obj_type) + " id " + str(obj_id) + " with JSON data: " + str(json_data))
    Session = sessionmaker(bind = engine)
    session = Session()
    obj_type_str = str(obj_type.__table__.name).upper()
    DBLogger.debug("obj_type_str is " + str(obj_type_str))
    filter_input = eval(obj_type_str + "." + obj_type_str.lower() + "_id==obj_id")

    try:
        sessionquery = session.query(obj_type).filter(filter_input)
        DBLogger.debug("got result: " + str(sessionquery.__dict__))
        sessionquery.update(json_data, synchronize_session = False)
    except Exception as E:
        DBLogger.error("Failed to query, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)

    

    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    
    session.close()
    return GetObj(obj_type, obj_id)

def DeleteObj(obj_type, obj_id):
    DBLogger.debug("Called DeleteObj for type " + str(obj_type) + " with id " + str(obj_id))

    Session = sessionmaker(bind = engine)
    session = Session()

    res = session.query(obj_type).get(obj_id)
    session.delete(res)
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    session.close()

def CreateObj(obj_type, json_data):
    newObj = obj_type(**json_data)
    Session = sessionmaker(bind = engine)
    session = Session()

    session.add(newObj)
    try:
        session.commit()
        session.refresh(newObj)
        result = newObj.__dict__
        result.pop('_sa_instance_state')
        session.close()
        return result
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)

def Generate_JSON_Model_for_Flask(obj_type):
    DBLogger.debug("Generating JSON model for Flask for object type: " + str(obj_type))
    from alchemyjsonschema import SchemaFactory
    from alchemyjsonschema import ForeignKeyWalker
    import pprint as pp
    factory = SchemaFactory(ForeignKeyWalker)
    dictty = dict(factory(obj_type))

    dictty['properties'] = dict(dictty['properties'])

    #Set the ID Object to not required
    obj_type_str = str(dictty['title']).lower()
    dictty['required'].remove(obj_type_str + '_id')


    return dictty

def Get_IMS_Subscriber(**kwargs):
    #Get subscriber by IMSI or MSISDN
    Session = sessionmaker(bind = engine)
    session = Session()
    if 'msisdn' in kwargs:
        DBLogger.debug("Get_IMS_Subscriber for msisdn " + str(kwargs['msisdn']))
        try:
            result = session.query(IMS_SUBSCRIBER).filter_by(msisdn=str(kwargs['msisdn'])).one()
        except Exception as E:
            session.close()
            raise ValueError(E)
    elif 'imsi' in kwargs:
        DBLogger.debug("Get_IMS_Subscriber for imsi " + str(kwargs['imsi']))
        try:
            result = session.query(IMS_SUBSCRIBER).filter_by(imsi=str(kwargs['imsi'])).one()
        except Exception as E:
            session.close()
            raise ValueError(E)
    DBLogger.debug("Converting result to dict")
    result = result.__dict__
    try:
        result.pop('_sa_instance_state')
    except:
        pass
    result = Sanitize_Datetime(result)
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    DBLogger.debug("Returning IMS Subscriber Data: " + str(result))
    session.close()
    return result

def Get_Subscriber(**kwargs):
    #Get subscriber by IMSI or MSISDN

    Session = sessionmaker(bind = engine)
    session = Session()

    if 'msisdn' in kwargs:
        DBLogger.debug("Get_Subscriber for msisdn " + str(kwargs['msisdn']))
        try:
            result = session.query(SUBSCRIBER).filter_by(msisdn=str(kwargs['msisdn'])).one()
        except Exception as E:
            session.close()
            raise ValueError(E)
    elif 'imsi' in kwargs:
        DBLogger.debug("Get_Subscriber for imsi " + str(kwargs['imsi']))
        try:
            result = session.query(SUBSCRIBER).filter_by(imsi=str(kwargs['imsi'])).one()
        except Exception as E:
            session.close()
            raise ValueError(E)
       
    result = result.__dict__
    result = Sanitize_Datetime(result)
    result.pop('_sa_instance_state')
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    DBLogger.debug("Got back result: " + str(result))
    session.close()
    return result

def Get_Served_Subscribers():
    DBLogger.debug("Getting all subscribers served by this HSS")

    Session = sessionmaker(bind = engine)
    session = Session()

    Served_Subs = {}
    try:
        results = session.query(SUBSCRIBER).filter(SUBSCRIBER.serving_mme.isnot(None))
        for result in results:
            result = result.__dict__
            DBLogger.debug("Result: " + str(result) + " type: " + str(type(result)))
            result = Sanitize_Datetime(result)
            result.pop('_sa_instance_state')
            Served_Subs[result['imsi']] = result
            DBLogger.debug("Processed result")
    except Exception as E:
        session.close()
        raise ValueError(E)
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    DBLogger.debug("Final Served_Subs: " + str(Served_Subs))
    session.close()
    return Served_Subs 

def Get_Served_IMS_Subscribers():
    DBLogger.debug("Getting all subscribers served by this IMS-HSS")
    Session = sessionmaker(bind = engine)
    session = Session()

    Served_Subs = {}
    try:
        results = session.query(IMS_SUBSCRIBER).filter(IMS_SUBSCRIBER.scscf.isnot(None))
        for result in results:
            result = result.__dict__
            DBLogger.debug("Result: " + str(result) + " type: " + str(type(result)))
            result = Sanitize_Datetime(result)
            result.pop('_sa_instance_state')
            Served_Subs[result['imsi']] = result
            DBLogger.debug("Processed result")
    except Exception as E:
        session.close()
        raise ValueError(E)
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    DBLogger.debug("Final Served_Subs: " + str(Served_Subs))
    session.close()
    return Served_Subs 

def Get_Served_PCRF_Subscribers():
    DBLogger.debug("Getting all subscribers served by this PCRF")
    Session = sessionmaker(bind = engine)
    session = Session()    
    Served_Subs = {}
    try:
        results = session.query(SERVING_APN).all()
        for result in results:
            result = result.__dict__
            DBLogger.debug("Result: " + str(result) + " type: " + str(type(result)))
            result = Sanitize_Datetime(result)
            result.pop('_sa_instance_state')
            #Get APN Info
            apn_info = GetObj(APN, result['apn'])
            DBLogger.debug("Got APN Info: " + str(apn_info))
            result['apn_info'] = apn_info
            
            #Get Subscriber Info
            subscriber_info = GetObj(SUBSCRIBER, result['subscriber_id'])
            result['subscriber_info'] = subscriber_info
            
            DBLogger.debug("Got Subscriber Info: " + str(subscriber_info))
            
            Served_Subs[subscriber_info['imsi']] = result
            DBLogger.debug("Processed result")
    except Exception as E:
        raise ValueError(E)
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)     
    DBLogger.debug("Final SERVING_APN: " + str(Served_Subs))
    session.close()
    return Served_Subs 

def Get_Vectors_AuC(auc_id, action, **kwargs):
    DBLogger.debug("Getting Vectors for auc_id " + str(auc_id) + " with action " + str(action))
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

    elif action == "sqn_resync":
        DBLogger.debug("Resync SQN")
        rand = kwargs['rand']       
        sqn, mac_s = S6a_crypt.generate_resync_s6a(key_data['ki'], key_data['opc'], key_data['amf'], kwargs['auts'], rand)
        DBLogger.debug("SQN from resync: " + str(sqn) + " SQN in DB is "  + str(key_data['sqn']) + "(Difference of " + str(int(sqn) - int(key_data['sqn'])) + ")")
        Update_AuC(auc_id, sqn=sqn+100)
        return
    
    elif action == "sip_auth":
        rand, autn, xres, ck, ik = S6a_crypt.generate_maa_vector(key_data['ki'], key_data['opc'], key_data['amf'], key_data['sqn'], kwargs['plmn'])
        DBLogger.debug("RAND is: " + str(rand))
        DBLogger.debug("AUTN is: " + str(autn))
        vector_dict['SIP_Authenticate'] = rand + autn
        vector_dict['xres'] = xres
        vector_dict['ck'] = ck
        vector_dict['ik'] = ik
        Update_AuC(auc_id, sqn=key_data['sqn']+100)
        return vector_dict

def Get_APN(apn_id):
    DBLogger.debug("Getting APN " + str(apn_id))
    Session = sessionmaker(bind = engine)
    session = Session()

    try:
        result = session.query(APN).filter_by(apn_id=apn_id).one()
    except Exception as E:
        session.close()
        raise ValueError(E)
    result = result.__dict__
    result.pop('_sa_instance_state')
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    session.close()
    return result    

def Get_APN_by_Name(apn):
    DBLogger.debug("Getting APN named " + str(apn_id))
    Session = sessionmaker(bind = engine)
    session = Session()    
    try:
        result = session.query(APN).filter_by(apn=str(apn)).one()
    except Exception as E:
        session.close()
        raise ValueError(E)
    result = result.__dict__
    result.pop('_sa_instance_state')
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    session.close()
    return result 

def Update_AuC(auc_id, sqn=1):
    DBLogger.debug("Updating AuC record for sub " + str(auc_id))
    DBLogger.debug(UpdateObj(AUC, {'sqn': sqn}, auc_id))
    return

def Update_Serving_MME(imsi, serving_mme, propagate=True):
    DBLogger.debug("Updating Serving MME for sub " + str(imsi) + " to MME " + str(serving_mme))
    Session = sessionmaker(bind = engine)
    session = Session()
    try:
        result = session.query(SUBSCRIBER).filter_by(imsi=imsi).one()
    except Exception as E:
        DBLogger.error("Failed to query session, error: " + str(E))
        session.rollback()
        session.close()

    if type(serving_mme) == str:
        DBLogger.debug("Updating serving MME")
        result.serving_mme = serving_mme
        result.serving_mme_timestamp = datetime.datetime.now()
    else:
        #Clear values
        DBLogger.debug("Clearing serving MME")
        result.serving_mme = None
        result.serving_mme_timestamp = None
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)

    #Sync state change with geored
    if propagate == True:
        try:
            if 'HSS' in yaml_config['geored']['sync_actions'] and yaml_config['geored']['enabled'] == True:
                DBLogger.debug("Propagate MME changes to Geographic PyHSS instances")
                GeoRed_Push_Async({"imsi": str(imsi), "serving_mme": result.serving_mme})
            else:
                DBLogger.debug("Config does not allow sync of HSS events")
        except Exception as E:
            DBLogger.debug("Nothing synced to Geographic PyHSS instances for HSS event")
            DBLogger.debug(E)

    session.close()
    return

def Update_Serving_CSCF(imsi, serving_cscf, propagate=True):
    DBLogger.debug("Update_Serving_CSCF for sub " + str(imsi) + " to SCSCF " + str(serving_cscf))
    Session = sessionmaker(bind = engine)
    session = Session()

    result = session.query(IMS_SUBSCRIBER).filter_by(imsi=imsi).one()
    if type(serving_cscf) == str:
        DBLogger.debug("Setting serving CSCF")
        result.scscf = serving_cscf
        result.scscf_timestamp = datetime.datetime.now()
    else:
        #Clear values
        DBLogger.debug("Clearing serving CSCF")
        result.scscf = None
        result.scscf_timestamp = None
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)


    #Sync state change with geored
    if propagate == True:
        try:
            if 'IMS' in yaml_config['geored']['sync_actions'] and yaml_config['geored']['enabled'] == True:
                DBLogger.debug("Propagate IMS changes to Geographic PyHSS instances")
                GeoRed_Push_Async({"imsi": str(imsi), "scscf": result.scscf})
            else:
                DBLogger.debug("Config does not allow sync of IMS events")
        except Exception as E:
            DBLogger.debug("Nothing synced to Geographic PyHSS instances for IMS event")
    session.close()
    return    

def Update_Serving_APN(imsi, apn, pcrf_session_id, serving_pgw, ue_ip, propagate=True):
    DBLogger.debug("Called Update_Serving_APN()")

    #Get Subscriber ID from IMSI
    subscriber_details = Get_Subscriber(imsi=str(imsi))
    subscriber_id = subscriber_details['subscriber_id']

    #Split the APN list into a list
    apn_list = subscriber_details['apn_list'].split(',')
    DBLogger.debug("Current APN List: " + str(apn_list))
    #Remove the default APN from the list
    try:
        apn_list.remove(str(subscriber_details['default_apn']))
    except:
        DBLogger.debug("Failed to remove default APN (" + str(subscriber_details['default_apn']) + " from APN List")
        pass
    #Add default APN in first position
    apn_list.insert(0, str(subscriber_details['default_apn']))

    #Get APN ID from APN
    for apn_id in apn_list:
        #Get each APN in List
        apn_data = Get_APN(apn_id)
        DBLogger.debug(apn_data)
        if str(apn_data['apn']).lower() == str(apn).lower():
            DBLogger.debug("Matched named APN with APN ID")
            json_data = {
                'apn' : apn_id,
                'subscriber_id' : subscriber_id,
                'pcrf_session_id' : str(pcrf_session_id),
                'serving_pgw' : str(serving_pgw),
                'serving_pgw_timestamp' : datetime.datetime.now(),
                'ue_ip' : str(ue_ip)
            }

            try:
            #Check if already a serving APN on record
                ServingAPN = Get_Serving_APN(subscriber_id=subscriber_id, apn_id=apn_id)
                DBLogger.debug("Existing Serving APN ID on record, updating")
                if type(serving_pgw) == str:
                    UpdateObj(SERVING_APN, json_data, ServingAPN['serving_apn_id'])
                else:
                    DBLogger.debug("Clearing PCRF session ID")
                    DeleteObj(SERVING_APN, ServingAPN['serving_apn_id'])
            except Exception as E:
                DBLogger.info("Failed to update existing APN " + str(E))
                #Update if does not exist
                CreateObj(SERVING_APN, json_data)

            #Sync state change with geored
            if propagate == True:
                try:
                    if 'PCRF' in yaml_config['geored']['sync_actions'] and yaml_config['geored']['enabled'] == True:
                        DBLogger.debug("Propagate PCRF changes to Geographic PyHSS instances")
                        GeoRed_Push_Async({"imsi": str(imsi),
                                        'pcrf_session_id': str(pcrf_session_id),
                                        'serving_pgw': str(serving_pgw),
                                        'ue_ip': str(ue_ip)
                                        })
                    else:
                        DBLogger.debug("Config does not allow sync of PCRF events")
                except Exception as E:
                    DBLogger.debug("Nothing synced to Geographic PyHSS instances for event PCRF")


            return

def Get_Serving_APN(subscriber_id, apn_id):
    DBLogger.debug("Getting Serving APN " + str(apn_id) + " with subscriber_id " + str(subscriber_id))
    Session = sessionmaker(bind = engine)
    session = Session()

    try:
        result = session.query(SERVING_APN).filter_by(subscriber_id=subscriber_id, apn=apn_id).one()
    except Exception as E:
        DBLogger.debug(E)
        session.close()
        raise ValueError(E)
    result = result.__dict__
    result.pop('_sa_instance_state')
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    
    session.close()
    return result   

def Get_Charging_Rule(charging_rule_id):
    DBLogger.debug("Called Get_Charging_Rule() for  charging_rule_id " + str(charging_rule_id))
    Session = sessionmaker(bind = engine)
    session = Session()
    #Get base Rule
    ChargingRule = GetObj(CHARGING_RULE, charging_rule_id)
    ChargingRule['tft'] = []
    #Get TFTs
    try:
        results = session.query(TFT).filter_by(tft_group_id=ChargingRule['tft_group_id'])
        for result in results:
            result = result.__dict__
            result.pop('_sa_instance_state')
            ChargingRule['tft'].append(result)
    except Exception as E:
        session.close()
        raise ValueError(E)
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    session.close()
    return ChargingRule

def Get_Charging_Rules(imsi, apn):
    DBLogger.debug("Called Get_Charging_Rules() for IMSI " + str(imsi) + " and APN " + str(apn))
    #Get Subscriber ID from IMSI
    subscriber_details = Get_Subscriber(imsi=str(imsi))

    #Split the APN list into a list
    apn_list = subscriber_details['apn_list'].split(',')
    DBLogger.debug("Current APN List: " + str(apn_list))
    #Remove the default APN from the list
    try:
        apn_list.remove(str(subscriber_details['default_apn']))
    except:
        DBLogger.debug("Failed to remove default APN (" + str(subscriber_details['default_apn']) + " from APN List")
        pass
    #Add default APN in first position
    apn_list.insert(0, str(subscriber_details['default_apn']))

    #Get APN ID from APN
    for apn_id in apn_list:
        DBLogger.debug("Getting APN ID " + str(apn_id) + " to see if it matches APN " + str(apn))
        #Get each APN in List
        apn_data = Get_APN(apn_id)
        DBLogger.debug(apn_data)
        if str(apn_data['apn']).lower() == str(apn).lower():
            DBLogger.debug("Matched named APN with APN ID")

            DBLogger.debug("Getting charging rule list from " + str(apn_data['charging_rule_list']))
            ChargingRule = {}
            ChargingRule['charging_rule_list'] = str(apn_data['charging_rule_list']).split(',')
            ChargingRule['apn_data'] = apn_data

            #Get Charging Rules list
            if apn_data['charging_rule_list'] == None:
                DBLogger.debug("No Charging Rule associated with this APN")
                ChargingRule['charging_rules'] = None
                return ChargingRule

            DBLogger.debug("ChargingRule['charging_rule_list'] is: " + str(ChargingRule['charging_rule_list']))
            #Empty dict for the Charging Rules to go into
            ChargingRule['charging_rules'] = []
            #Add each of the Charging Rules for the APN
            for individual_charging_rule in ChargingRule['charging_rule_list']:
                DBLogger.debug("Getting Charging rule " + str(individual_charging_rule))
                individual_charging_rule_complete = Get_Charging_Rule(individual_charging_rule)
                DBLogger.debug("Got individual_charging_rule_complete: " + str(individual_charging_rule_complete))
                ChargingRule['charging_rules'].append(individual_charging_rule_complete)
            DBLogger.debug("Completed Get_Charging_Rules()")
            DBLogger.debug(ChargingRule)
            return ChargingRule

def Get_Serving_APN_Subscriber(subscriber_id, apn_id):
    DBLogger.debug("Getting Serving APN " + str(apn_id) + " with subscriber_id " + str(subscriber_id))
    try:
        Session = sessionmaker(bind = engine)
        session = Session()
        result = session.query(SERVING_APN).filter_by(subscriber_id=subscriber_id, apn=apn_id).one()
    except Exception as E:
        session.close()
        raise ValueError(E)

    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    session.close()

    result = result.__dict__
    result.pop('_sa_instance_state')
    return result

def Store_IMSI_IMEI_Binding(imsi, imei, match_response_code, propagate=True):
    #IMSI           14-15 Digits
    #IMEI           15 Digits
    #IMEI-SV        2 Digits
    DBLogger.debug("Called Store_IMSI_IMEI_Binding() with IMSI: " + str(imsi) + " IMEI: " + str(imei) + " match_response_code: " + str(match_response_code))
    if yaml_config['eir']['imsi_imei_logging'] != True:
        DBLogger.debug("Skipping storing binding")
        return
    #Concat IMEI + IMSI
    imsi_imei = str(imsi) + "," + str(imei)
    Session = sessionmaker(bind = engine)
    session = Session()

    #Check if exist already & update
    try:
        session.query(IMSI_IMEI_HISTORY).filter_by(imsi_imei=imsi_imei).one()
        DBLogger.debug("Entry already present for IMSI/IMEI Combo")   
        session.close()     
        return 
    except Exception as E:
        newObj = IMSI_IMEI_HISTORY(imsi_imei=imsi_imei, match_response_code=match_response_code, imsi_imei_timestamp = datetime.datetime.now())
        session.add(newObj)
        try:
            session.commit()
        except Exception as E:
            DBLogger.error("Failed to commit session, error: " + str(E))
            session.rollback()
            session.close()
            raise ValueError(E)
        DBLogger.debug("Added new IMSI_IMEI_HISTORY binding")
        try:
            import grequests
            dictToSend = {'imei':imei, 'imsi': imsi, 'match_response_code': match_response_code}
            grequests.post(str(yaml_config['eir']['sim_swap_notify_webhook']), json=dictToSend)
        except Exception as E:
            DBLogger.debug("Failed to post to Webhook")
            DBLogger.debug(str(E))
        session.close()

        #Sync state change with geored
        if propagate == True:
            try:
                if 'EIR' in yaml_config['geored']['sync_actions'] and yaml_config['geored']['enabled'] == True:
                    DBLogger.debug("Propagate EIR changes to Geographic PyHSS instances")
                    GeoRed_Push_Async(
                        {"imsi": str(imsi), 
                        "imei": str(imei), 
                        "match_response_code": str(match_response_code)}
                        )
                else:
                    DBLogger.debug("Config does not allow sync of EIR events")
            except Exception as E:
                DBLogger.debug("Nothing synced to Geographic PyHSS instances for EIR event")
                DBLogger.debug(E)

        return

def Get_IMEI_IMSI_History(attribute):
    DBLogger.debug("Called Get_IMEI_IMSI_History() for entry matching " + str(Get_IMEI_IMSI_History))
    Session = sessionmaker(bind = engine)
    session = Session()
    result_array = []
    try:
        results = session.query(IMSI_IMEI_HISTORY).filter(IMSI_IMEI_HISTORY.imsi_imei.ilike("%" + str(attribute) + "%")).all()
        for result in results:
            result = result.__dict__
            result.pop('_sa_instance_state')
            result = Sanitize_Datetime(result)
            try:
                result['imsi'] = result['imsi_imei'].split(",")[0]
            except:
                continue
            try:
                result['imei'] = result['imsi_imei'].split(",")[1]
            except:
                continue                
            result_array.append(result)
        session.close()
        return result_array
    except Exception as E:
        session.close()
        raise ValueError(E)

def Check_EIR(imsi, imei):
    eir_response_code_table = {0 : 'Whitelist', 1: 'Blacklist', 2: 'Greylist'}
    DBLogger.debug("Called Check_EIR() for  imsi " + str(imsi) + " and imei: " + str(imei))
    Session = sessionmaker(bind = engine)
    session = Session()
    #Check for Exact Matches
    DBLogger.debug("Looking for exact matches")
    #Check for exact Matches
    try:
        results = session.query(EIR).filter_by(imei=str(imei), regex_mode=0)
        for result in results:
            result = result.__dict__
            match_response_code = result['match_response_code']
            if result['imsi'] == '':
                DBLogger.debug("No IMSI specified in DB, so matching only on IMEI")
                Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=match_response_code)
                return match_response_code
            elif result['imsi'] == str(imsi):
                DBLogger.debug("Matched on IMEI and IMSI")
                Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=match_response_code)
                return match_response_code
    except Exception as E:
        session.rollback()
        session.close()
        raise ValueError(E)
    
    DBLogger.debug("Did not match any Exact Matches - Checking Regex")   
    try:
        results = session.query(EIR).filter_by(regex_mode=1)    #Get all Regex records from DB
        for result in results:
            result = result.__dict__
            match_response_code = result['match_response_code']
            if re.match(result['imei'], imei):
                DBLogger.debug("IMEI matched " + str(result['imei']))
                #Check if IMSI also specified
                if len(result['imsi']) != 0:
                    DBLogger.debug("With IMEI matched, now checking if IMSI matches regex")
                    if re.match(result['imsi'], imsi):
                        DBLogger.debug("IMSI also matched, so match OK!")
                        Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=match_response_code)
                        return match_response_code
                else:
                    DBLogger.debug("No IMSI specified, so match OK!")
                    Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=match_response_code)
                    return match_response_code
    except Exception as E:
        session.rollback()
        session.close()
        raise ValueError(E)

    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    DBLogger.debug("No matches at all - Returning default response")
    Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=yaml_config['eir']['no_match_response'])
    session.close()
    return yaml_config['eir']['no_match_response']

def Get_EIR_Rules():
    DBLogger.debug("Getting all EIR Rules")
    Session = sessionmaker(bind = engine)
    session = Session()
    EIR_Rules = []
    try:
        results = session.query(EIR)
        for result in results:
            result = result.__dict__
            result.pop('_sa_instance_state')
            EIR_Rules.append(result)
    except Exception as E:
        session.rollback()
        session.close()
        raise ValueError(E)
    try:
        session.commit()
    except Exception as E:
        DBLogger.error("Failed to commit session, error: " + str(E))
        session.rollback()
        session.close()
        raise ValueError(E)
    DBLogger.debug("Final EIR_Rules: " + str(EIR_Rules))
    session.close()
    return EIR_Rules 


if __name__ == "__main__":
    import binascii,os,pprint
    DeleteAfter = True

    #Define Charging Rule
    charging_rule = {
        'rule_name' : 'charging_rule_A',
        'qci' : 4,
        'arp_priority' : 5,
        'arp_preemption_capability' : True,
        'arp_preemption_vulnerability' : False,
        'mbr_dl' : 128000,
        'mbr_ul' : 128000,
        'gbr_dl' : 128000,
        'gbr_ul' : 128000,
        'tft_group_id' : 1,
        'precedence' : 100,
        'rating_group' : 20000
        }
    print("Creating Charging Rule A")
    ChargingRule_newObj_A = CreateObj(CHARGING_RULE, charging_rule)
    print("ChargingRule_newObj A: " + str(ChargingRule_newObj_A))
    charging_rule['gbr_ul'], charging_rule['gbr_dl'], charging_rule['mbr_ul'], charging_rule['mbr_dl'] = 256000, 256000, 256000, 256000
    print("Creating Charging Rule B")
    charging_rule['rule_name'], charging_rule['precedence'], charging_rule['tft_group_id'] = 'charging_rule_B', 80, 2
    ChargingRule_newObj_B = CreateObj(CHARGING_RULE, charging_rule)
    print("ChargingRule_newObj B: " + str(ChargingRule_newObj_B))

    #Define TFTs
    tft_template1 = {
        'tft_group_id' : 1,
        'tft_string' : 'permit out ip from any to any',
        'direction' : 1
    }
    tft_template2 = {
        'tft_group_id' : 1,
        'tft_string' : 'permit out ip from any to any',
        'direction' : 2
    }
    print("Creating TFT")
    CreateObj(TFT, tft_template1)
    CreateObj(TFT, tft_template2)

    tft_template3 = {
        'tft_group_id' : 2,
        'tft_string' : 'permit out ip from 10.98.0.0 255.255.255.0 to any',
        'direction' : 1
    }
    tft_template4 = {
        'tft_group_id' : 2,
        'tft_string' : 'permit out ip from any to 10.98.0.0 255.255.255.0',
        'direction' : 2
    }
    print("Creating TFT")
    CreateObj(TFT, tft_template3)
    CreateObj(TFT, tft_template4)


    apn2 = {
        'apn':'ims',
        'apn_ambr_dl' : 9999, 
        'apn_ambr_ul' : 9999,
        'arp_priority': 1, 
        'arp_preemption_capability' : False,
        'arp_preemption_vulnerability': True,
        'charging_rule_list' : str(ChargingRule_newObj_A['charging_rule_id']) + "," + str(ChargingRule_newObj_B['charging_rule_id'])
        }
    print("Creating APN " + str(apn2['apn']))
    newObj = CreateObj(APN, apn2)
    print(newObj)

    print("Getting APN " + str(apn2['apn']))
    print(GetObj(APN, newObj['apn_id']))
    apn_id = newObj['apn_id']
    UpdatedObj = newObj
    UpdatedObj['apn'] = 'UpdatedInUnitTest'
    
    print("Updating APN " + str(apn2['apn']))
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
    print("Creating AuC entry")
    newObj = CreateObj(AUC, auc_json)
    print(newObj)

    #Get AuC
    print("Getting AuC entry")
    newObj = GetObj(AUC, newObj['auc_id'])
    auc_id = newObj['auc_id']
    print(newObj)

    #Update AuC
    print("Updating AuC entry")
    newObj['sqn'] = newObj['sqn'] + 10
    newObj = UpdateObj(AUC, newObj, auc_id)

    #Generate Vectors
    print("Generating Vectors")
    Get_Vectors_AuC(auc_id, "air", plmn='12ff')
    print(Get_Vectors_AuC(auc_id, "sip_auth", plmn='12ff'))


    #Update AuC
    Update_AuC(auc_id, sqn=100)

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
        existing_sub_data = Get_Subscriber(imsi=subscriber_json['imsi'])
        DeleteObj(SUBSCRIBER, existing_sub_data['subscriber_id'])
    except:
        print("Did not find old sub to delete")

    print("Creating new Subscriber")
    print(subscriber_json)
    newObj = CreateObj(SUBSCRIBER, subscriber_json)
    print(newObj)
    subscriber_id = newObj['subscriber_id']

    #Get SUBSCRIBER
    print("Getting Subscriber")
    newObj = GetObj(SUBSCRIBER, subscriber_id)
    print(newObj)

    #Update SUBSCRIBER
    print("Updating Subscriber")
    newObj['ue_ambr_ul'] = 999995
    newObj = UpdateObj(SUBSCRIBER, newObj, subscriber_id)

    #Set MME Location for Subscriber
    print("Updating Serving MME for Subscriber")
    Update_Serving_MME(newObj['imsi'], "Test123")

    #Update Serving APN for Subscriber
    print("Updating Serving APN for Subscriber")
    Update_Serving_APN(imsi=newObj['imsi'], apn=apn2['apn'], pcrf_session_id='kjsdlkjfd', serving_pgw='pgw.test.com', ue_ip='1.2.3.4')

    print("Getting Charging Rule for Subscriber / APN Combo")
    ChargingRule = Get_Charging_Rules(imsi=newObj['imsi'], apn=apn2['apn'])
    pprint.pprint(ChargingRule)

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
    print("Test Getting Subscriber")
    GetSubscriber_Result = Get_Subscriber(imsi=subscriber_json['imsi'])
    print(GetSubscriber_Result)

    #Test IMS Get Subscriber
    print("Getting IMS Subscribers")
    print(Get_IMS_Subscriber(imsi='001001000000006'))
    print(Get_IMS_Subscriber(msisdn='12345678'))

    #Set SCSCF for Subscriber
    Update_Serving_CSCF(newObj['imsi'], "NickTestCSCF")
    #Get Served Subscriber List
    print(Get_Served_IMS_Subscribers())

    #Clear Serving PGW for PCRF Subscriber
    print("Clear Serving PGW for PCRF Subscriber")
    Update_Serving_APN(imsi=newObj['imsi'], apn=apn2['apn'], pcrf_session_id='sessionid123', serving_pgw=None, ue_ip=None)

    #Clear MME Location for Subscriber    
    print("Clear MME Location for Subscriber")
    Update_Serving_MME(newObj['imsi'], None)

    #Generate Vectors for IMS Subscriber
    print("Generating Vectors for IMS Subscriber")
    print(Get_Vectors_AuC(auc_id, "sip_auth", plmn='12ff'))

    print("Generating Resync for IMS Subscriber")
    print(Get_Vectors_AuC(auc_id, "sqn_resync", auts='7964347dfdfe432289522183fcfb', rand='1bc9f096002d3716c65e4e1f4c1c0d17'))
    


    #Test getting APNs
    GetAPN_Result = Get_APN(GetSubscriber_Result['default_apn'])
    print(GetAPN_Result)

    #GeoRed_Push_Async({"imsi": "001001000000006", "serving_mme": "abc123"})
    

    if DeleteAfter == True:
        #Delete IMS Subscriber
        print(DeleteObj(IMS_SUBSCRIBER, ims_subscriber_id))
        #Delete Subscriber
        print(DeleteObj(SUBSCRIBER, subscriber_id))
        #Delete AuC
        print(DeleteObj(AUC, auc_id))
        #Delete APN
        print(DeleteObj(APN, apn_id))

    #Whitelist IMEI / IMSI Binding
    eir_template = {'imei': '1234', 'imsi': '567', 'regex_mode': 0, 'match_response_code': 0}
    CreateObj(EIR, eir_template)

    #Blacklist Example
    eir_template = {'imei': '99881232', 'imsi': '', 'regex_mode': 0, 'match_response_code': 1}
    CreateObj(EIR, eir_template)

    #IMEI Prefix Regex Example (Blacklist all IMEIs starting with 666)
    eir_template = {'imei': '^666.*', 'imsi': '', 'regex_mode': 1, 'match_response_code': 1}
    CreateObj(EIR, eir_template)

    #IMEI Prefix Regex Example (Greylist response for IMEI starting with 777 and IMSI is 1234123412341234)
    eir_template = {'imei': '^777.*', 'imsi': '^1234123412341234$', 'regex_mode': 1, 'match_response_code': 2}
    CreateObj(EIR, eir_template)

    print("\n\n\n\n")
    #Check Whitelist (No Match)
    assert Check_EIR(imei='1234', imsi='') == 2

    print("\n\n\n\n")
    #Check Whitelist (Matched)
    assert Check_EIR(imei='1234', imsi='567') == 0

    print("\n\n\n\n")
    #Check Blacklist (Match)
    assert Check_EIR(imei='99881232', imsi='567') == 1

    print("\n\n\n\n")
    #IMEI Prefix Regex Example (Greylist response for IMEI starting with 777 and IMSI is 1234123412341234)
    assert Check_EIR(imei='7771234', imsi='1234123412341234') == 2
    
    print(Get_IMEI_IMSI_History('1234123412'))


    print("\n\n\n")
    print(Generate_JSON_Model_for_Flask(SUBSCRIBER))


