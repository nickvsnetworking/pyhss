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

class Customers(Base):
   __tablename__ = 'customers'
   id = Column(Integer, primary_key=True)

   name = Column(String(50))
   address = Column(String(50))
   email = Column(String(50))

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

def GetAPN(apn_id):
    result = session.query(APN).filter(APN.apn_id==int(apn_id)).one()
    result = result.__dict__
    result.pop('_sa_instance_state')
    return result

def DeleteAPN(apn_id):
    session.query(APN).filter(APN.apn_id==int(apn_id)).delete()
    session.commit()
    return {"Result":"OK"}

def CreateAPN(apn_data):
    newAPN = APN(**apn_data)
    session.add(newAPN)
    session.commit()
    session.refresh(newAPN)
    return newAPN.apn_id

def UpdateAPN(apn_data):
    print("Called UpdateAPN() with JSON data: " + str(apn_data))
    print("Updating APN with ID " + str(apn_data['apn_id']))
    result = session.query(APN).filter(APN.apn_id==int(apn_data['apn_id']))
    print("got result: " + str(result.__dict__))
    result.update(apn_data, synchronize_session = False)
    session.commit()
    return apn_data

if __name__ == "__main__":
    # apn_id = 1
    # apn_data = GetAPN(apn_id)
    # print(apn_data)
    # apn_data = json.dumps(apn_data)
    # print(apn_data)
    # sys.exit()
    #apn1 = APN(apn='NickTest', apn_ambr_dl=9999, apn_ambr_ul=9999)
    apn2 = {'apn_id' : 11, 'apn':'fadsgdsags', \
        'apn_ambr_dl' : 9999, 'apn_ambr_ul' : 9999, \
        'arp_priority': 1, 'arp_preemption_capability' : False, \
        'arp_preemption_vulnerability': True}
    UpdateAPN(apn2)
    sys.exit()
    # session.add(apn1)
    # session.commit()
    # print("\n\n\n\n\n\n")
    # print(apn2)
    # newAPN = APN(**apn2)
    # print(newAPN)
    # session.add(newAPN)
    # session.commit()


    result = session.query(APN).filter(APN.apn_id==1).one()
    print(result)
    sys.exit()



