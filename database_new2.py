import sys
from sqlalchemy import Column, Integer, String, MetaData, Table, Boolean, ForeignKey, select, UniqueConstraint, DateTime
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.orm import sessionmaker
import json
#engine = create_engine('sqlite:///sales.db', echo = True)
engine = create_engine('mysql://dbeaver:password@localhost/hss2', echo = True)
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

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


class Subscriber(Base):
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

class IMS_Subscriber(Base):
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
    result = session.query(obj_type).get(obj_id)
    result = result.__dict__
    result.pop('_sa_instance_state')
    return result

def UpdateObj(obj_type, json_data, obj_id):
    print("Called UpdateObj() for type " + str(obj_type) + " id " + str(obj_id) + " with JSON data: " + str(json_data))
    result = session.query(obj_type).get(obj_id)
    print("got result: " + str(result.__dict__))
    result.update(json_data, synchronize_session = False)
    session.commit()
    result = result.__dict__
    result.pop('_sa_instance_state')
    return result

def UpdateObj(obj_type, apn_data, obj_id):
    print("Called UpdateObj() for object " + str(obj_type) + " ID " + str(obj_id) + " with JSON data: " + str(apn_data))
    result = session.query(obj_type).filter(APN.apn_id==int(obj_id))
    print("got result: " + str(result.__dict__))
    result.update(apn_data, synchronize_session = False)
    session.commit()
    return apn_data

def DeleteObj(obj_type, obj_id):
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
    return dictty

if __name__ == "__main__":

    import binascii,os
    apn2 = {'apn':'fadsgdsags', \
        'apn_ambr_dl' : 9999, 'apn_ambr_ul' : 9999, \
        'arp_priority': 1, 'arp_preemption_capability' : False, \
        'arp_preemption_vulnerability': True}
    newObj = CreateObj(APN, apn2)
    print(newObj)
    #input("Created new Object")
    print(GetObj(APN, newObj['apn_id']))
    newObj['apn'] = 'updatedonapn'
    newObj = UpdateObj(APN, newObj, newObj['apn_id'])
    print(newObj)
    #input("Updated new Object")
    print(DeleteObj(APN, newObj['apn_id']))

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
    print(GetObj(AUC, newObj['auc_id']))

    #Update AuC (failing)
    newObj['sqn'] = newObj['sqn'] + 10
    newObj = UpdateObj(AUC, newObj, newObj['auc_id'])

    #Delete AuC
    print(DeleteObj(AUC, newObj['auc_id']))

