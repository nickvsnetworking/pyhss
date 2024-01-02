from sqlalchemy import Column, Integer, String, MetaData, Table, Boolean, ForeignKey, select, UniqueConstraint, DateTime, BigInteger, Text, DateTime, Float
from sqlalchemy import create_engine
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.sql import desc, func
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.orm import sessionmaker, relationship, Session, class_mapper
from sqlalchemy.orm.attributes import History, get_history
from sqlalchemy.ext.declarative import declarative_base
import  os
import datetime, time
from datetime import timezone
import re
import binascii
import uuid
import socket
import pprint
import S6a_crypt
from messaging import RedisMessaging
import yaml
import json
import traceback

with open("../config.yaml", 'r') as stream:
    config = (yaml.safe_load(stream))


Base = declarative_base()
class APN(Base):
    __tablename__ = 'apn'
    apn_id = Column(Integer, primary_key=True, doc='Unique ID of APN')
    apn = Column(String(50), nullable=False, doc='Short name of the APN')
    ip_version = Column(Integer, default=0, doc="IP version used - 0: ipv4, 1: ipv6 2: ipv4+6 3: ipv4 or ipv6 4:  [3GPP TS 29.272 7.3.62]")
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
    nbiot = Column(Boolean, default=0, doc="Whether this APN provides NBIoT")
    nidd_scef_id = Column(String(512), default=None, doc="ID of SCEF to be used for NIDD for NB-IoT")
    nidd_scef_realm = Column(String(512), default=None, doc='Realm of the SCEF for NIDD for NB-IoT')
    nidd_mechanism = Column(Integer, default=None, doc="Mechanism used to transfer Non-IP-Data: SGi-BASED-DATA-DELIVERY (0) or SCEF-BASED-DATA-DELIVERY (1)")
    nidd_rds = Column(Integer, default=None, doc="Indicates if Reliable Data Service is enabled or disabled for this APN: DISABLED (0) or ENABLED (1)")
    nidd_preferred_data_mode = Column(Integer, default=None, doc="Preferred-Data-Mode: Data over User Plane Preferred (0) or Data over Control Plane Preferred (1)")
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("APN_OPERATION_LOG", back_populates="apn")

class AUC(Base):
    __tablename__ = 'auc'
    auc_id = Column(Integer, primary_key = True, doc='Unique ID of AuC entry')
    ki = Column(String(32), doc='SIM Key - Authentication Key - Ki', nullable=False)
    opc = Column(String(32), doc='SIM Key - Network Operators key OPc', nullable=False)
    amf = Column(String(4), doc='Authentication Management Field', nullable=False)
    sqn = Column(BigInteger, doc='Authentication sequence number')
    iccid = Column(String(20), unique=True, doc='Integrated Circuit Card Identification Number')
    imsi = Column(String(18), unique=True, doc='International Mobile Subscriber Identity')
    batch_name = Column(String(20), doc='Name of SIM Batch')
    sim_vendor = Column(String(20), doc='SIM Vendor')
    esim = Column(Boolean, default=0, doc='Card is eSIM')
    lpa = Column(String(128), doc='LPA URL for activating eSIM')
    pin1 = Column(String(20), doc='PIN1')
    pin2 = Column(String(20), doc='PIN2')
    puk1 = Column(String(20), doc='PUK1')
    puk2 = Column(String(20), doc='PUK2')
    kid = Column(String(20), doc='KID')
    psk = Column(String(128), doc='PSK')
    des = Column(String(128), doc='DES')
    adm1 = Column(String(20), doc='ADM1')
    misc1 = Column(String(128), doc='For misc data storage 1')
    misc2 = Column(String(128), doc='For misc data storage 2')
    misc3 = Column(String(128), doc='For misc data storage 3')
    misc4 = Column(String(128), doc='For misc data storage 4')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("AUC_OPERATION_LOG", back_populates="auc")
    
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
    nam = Column(Integer, default=0, doc='Network Access Mode [3GPP TS. 123 008 2.1.1.2] - 0 (PACKET_AND_CIRCUIT) or 2 (ONLY_PACKET)')
    roaming_enabled = Column(Boolean, default=1, doc='Whether or not to enable roaming on this subscriber')
    roaming_rule_list = Column(String(512), doc='Comma separated list of roaming rules applicable to this subscriber')
    subscribed_rau_tau_timer = Column(Integer, default=300, doc='Subscribed periodic TAU/RAU timer value in seconds')
    serving_mme = Column(String(512), doc='MME serving this subscriber')
    serving_mme_timestamp = Column(DateTime, doc='Timestamp of attach to MME')
    serving_mme_realm = Column(String(512), doc='Realm of serving mme')
    serving_mme_peer = Column(String(512), doc='Diameter peer used to reach MME then ; then the HSS the Diameter peer is connected to')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("SUBSCRIBER_OPERATION_LOG", back_populates="subscriber")


class SUBSCRIBER_ROUTING(Base):
    __tablename__ = 'subscriber_routing'
    __table_args__ = (
        # this can be db.PrimaryKeyConstraint if you want it to be a primary key
        UniqueConstraint('subscriber_id', 'apn_id'),
    )
    subscriber_routing_id = Column(Integer, primary_key=True, doc='Unique ID of Subscriber Routing item')
    subscriber_id = Column(Integer, ForeignKey('subscriber.subscriber_id', ondelete='CASCADE'), doc='subscriber_id of the served subscriber')
    apn_id = Column(Integer, ForeignKey('apn.apn_id', ondelete='CASCADE'), doc='apn_id of the target apn')
    ip_version = Column(Integer, default=0, doc="IP version used - 0: ipv4, 1: ipv6 2: ipv4+6 3: ipv4 or ipv6 [3GPP TS 29.272 7.3.62]")
    ip_address = Column(String(254), doc='IP of the UE')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("SUBSCRIBER_ROUTING_OPERATION_LOG", back_populates="subscriber_routing")


class SERVING_APN(Base):
    __tablename__ = 'serving_apn'
    serving_apn_id = Column(Integer, primary_key=True, doc='Unique ID of SERVING_APN')
    subscriber_id = Column(Integer, ForeignKey('subscriber.subscriber_id', ondelete='CASCADE'), doc='subscriber_id of the served subscriber')
    apn = Column(Integer, ForeignKey('apn.apn_id', ondelete='CASCADE'), doc='apn_id of the APN served')
    pcrf_session_id = Column(String(100), doc='Session ID from the PCRF')
    subscriber_routing = Column(String(100), doc='IP Address allocated to the UE')
    ip_version = Column(Integer, default=0, doc=APN.ip_version.doc)
    serving_pgw = Column(String(512), doc='PGW serving this subscriber')
    serving_pgw_timestamp = Column(DateTime, doc='Timestamp of attach to PGW')
    serving_pgw_realm = Column(String(512), doc='Realm of serving PGW')
    serving_pgw_peer = Column(String(512), doc='Diameter peer used to reach PGW')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("SERVING_APN_OPERATION_LOG", back_populates="serving_apn")

# Legacy support for sh_profile. sh_profile is deprecated as of v1.0.1.
class IMS_SUBSCRIBER(Base):
    __tablename__ = 'ims_subscriber'
    ims_subscriber_id = Column(Integer, primary_key = True, doc='Unique ID of IMS_Subscriber entry')
    msisdn = Column(String(18), unique=True, doc=SUBSCRIBER.msisdn.doc)
    msisdn_list = Column(String(1200), doc='Comma Separated list of additional MSISDNs for Subscriber')
    imsi = Column(String(18), unique=False, doc=SUBSCRIBER.imsi.doc)
    ifc_path = Column(String(512), doc='Path to template file for the Initial Filter Criteria')
    pcscf = Column(String(512), doc='Proxy-CSCF serving this subscriber')
    pcscf_realm = Column(String(512), doc='Realm of PCSCF')
    pcscf_active_session = Column(String(512), doc='Session Id for the PCSCF when in a call')
    pcscf_timestamp = Column(DateTime, doc='Timestamp of last ue attach to PCSCF')
    pcscf_peer = Column(String(512), doc='Diameter peer used to reach PCSCF')
    # Conditional column definition based on the database type
    if 'mysql' in str(config['database']['db_type']).lower():
        xcap_profile = Column(Text(12000), doc='XCAP Subscriber Profile')
        sh_profile = Column(Text(12000), doc='Deprecated - XCAP Subscriber Profile')
    else:
        xcap_profile = Column(Text, doc='XCAP Subscriber Profile')
        sh_profile = Column(Text, doc='Deprecated - XCAP Subscriber Profile')
    scscf = Column(String(512), doc='Serving-CSCF serving this subscriber')
    scscf_timestamp = Column(DateTime, doc='Timestamp of last ue attach to SCSCF')
    scscf_realm = Column(String(512), doc='Realm of SCSCF')
    scscf_peer = Column(String(512), doc='Diameter peer used to reach SCSCF')
    sh_template_path = Column(String(512), doc='Path to template file for the Sh Profile')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("IMS_SUBSCRIBER_OPERATION_LOG", back_populates="ims_subscriber")

class ROAMING_RULE(Base):
    __tablename__ = 'roaming_rule'
    roaming_rule_id = Column(Integer, primary_key = True, doc='Unique ID of ROAMING_RULE entry')
    roaming_network_id = Column(Integer, ForeignKey('roaming_network.roaming_network_id', ondelete='CASCADE'), doc='ID of the roaming network to apply the rule for')
    allow = Column(Boolean, default=1, doc='Whether to allow outbound roaming on the network')
    enabled = Column(Boolean, default=1, doc='Whether the rule is enabled')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("ROAMING_RULE_OPERATION_LOG", back_populates="roaming_rule")

class ROAMING_NETWORK(Base):
    __tablename__ = 'roaming_network'
    roaming_network_id = Column(Integer, primary_key = True, doc='Unique ID of ROAMING_NETWORK entry')
    name = Column(String(512), doc='Name of the roaming network')
    preference = Column(Integer, default=1, doc='Preference of the network. Lower numbers are chosen first.')
    mcc = Column(String(100), doc='MCC to apply the roaming rule for')
    mnc = Column(String(100), doc='3 digit MNC to apply the roaming rule for')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("ROAMING_NETWORK_OPERATION_LOG", back_populates="roaming_network")

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
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("CHARGING_RULE_OPERATION_LOG", back_populates="charging_rule")
    
class TFT(Base):
    __tablename__ = 'tft'
    tft_id = Column(Integer, primary_key = True, doc='Unique ID of CHARGING_RULE entry')
    tft_group_id = Column(Integer, nullable=False, doc=CHARGING_RULE.tft_group_id.doc)
    tft_string = Column(String(100), nullable=False, doc='IPFilterRules as defined in [RFC 6733] taking the format: action dir proto from src to dst')
    direction = Column(Integer, nullable=False, doc='Traffic Direction: 0- Unspecified, 1 - Downlink, 2 - Uplink, 3 - Bidirectional')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("TFT_OPERATION_LOG", back_populates="tft")

class EIR(Base):
    __tablename__ = 'eir'
    eir_id = Column(Integer, primary_key = True, doc='Unique ID of EIR entry')
    imei = Column(String(60), doc='Exact IMEI or Regex to match IMEI (Depending on regex_mode value)')
    imsi = Column(String(60), doc='Exact IMSI or Regex to match IMSI (Depending on regex_mode value)')
    regex_mode = Column(Integer, default=1, doc='0 - Exact Match mode, 1 - Regex Mode')
    match_response_code = Column(Integer, doc='0 - Whitelist, 1 - Blacklist, 2 - Greylist')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("EIR_OPERATION_LOG", back_populates="eir")

class IMSI_IMEI_HISTORY(Base):
    __tablename__ = 'eir_history'
    imsi_imei_history_id = Column(Integer, primary_key = True, doc='Unique ID of IMSI_IMEI_HISTORY entry')
    imsi_imei = Column(String(60), unique=True, doc='Combined IMSI + IMEI value')
    match_response_code = Column(Integer, doc='Response code that was returned')
    imsi_imei_timestamp = Column(DateTime, doc='Timestamp of last match')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    operation_logs = relationship("IMSI_IMEI_HISTORY_OPERATION_LOG", back_populates="eir_history")

class SUBSCRIBER_ATTRIBUTES(Base):
    __tablename__ = 'subscriber_attributes'
    subscriber_attributes_id = Column(Integer, primary_key = True, doc='Unique ID of Attribute')
    subscriber_id = Column(Integer, ForeignKey('subscriber.subscriber_id', ondelete='CASCADE'), doc='Reference to Subscriber ID defined within Subscriber Section', nullable=False)
    key = Column(String(60), doc='Arbitrary key')
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc), doc='Timestamp of last modification')
    value = Column(String(12000), doc='Arbitrary value')
    operation_logs = relationship("SUBSCRIBER_ATTRIBUTES_OPERATION_LOG", back_populates="subscriber_attributes")

class OPERATION_LOG_BASE(Base):
    __tablename__ = 'operation_log'
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, nullable=False)
    operation_id = Column(String(36), nullable=False)
    operation = Column(String(10))
    changes = Column(Text)
    last_modified = Column(String(100), default=datetime.datetime.now(tz=timezone.utc))
    timestamp = Column(DateTime, default=func.now())
    table_name = Column('table_name', String(255))
    __mapper_args__ = {'polymorphic_on': table_name}

class APN_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'apn'}
    apn = relationship("APN", back_populates="operation_logs")
    apn_id = Column(Integer, ForeignKey('apn.apn_id'))

class SUBSCRIBER_ROUTING_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'subscriber_routing'}
    subscriber_routing = relationship("SUBSCRIBER_ROUTING", back_populates="operation_logs")
    subscriber_routing_id = Column(Integer, ForeignKey('subscriber_routing.subscriber_routing_id'))

class SERVING_APN_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'serving_apn'}
    serving_apn = relationship("SERVING_APN", back_populates="operation_logs")
    serving_apn_id = Column(Integer, ForeignKey('serving_apn.serving_apn_id'))

class AUC_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'auc'}
    auc = relationship("AUC", back_populates="operation_logs")
    auc_id = Column(Integer, ForeignKey('auc.auc_id'))

class SUBSCRIBER_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'subscriber'}
    subscriber = relationship("SUBSCRIBER", back_populates="operation_logs")
    subscriber_id = Column(Integer, ForeignKey('subscriber.subscriber_id'))

class IMS_SUBSCRIBER_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'ims_subscriber'}
    ims_subscriber = relationship("IMS_SUBSCRIBER", back_populates="operation_logs")
    ims_subscriber_id = Column(Integer, ForeignKey('ims_subscriber.ims_subscriber_id'))

class ROAMING_RULE_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'roaming_rule'}
    roaming_rule = relationship("ROAMING_RULE", back_populates="operation_logs")
    roaming_rule_id = Column(Integer, ForeignKey('roaming_rule.roaming_rule_id'))

class ROAMING_NETWORK_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'roaming_network'}
    roaming_network = relationship("ROAMING_NETWORK", back_populates="operation_logs")
    roaming_network_id = Column(Integer, ForeignKey('roaming_network.roaming_network_id'))

class CHARGING_RULE_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'charging_rule'}
    charging_rule = relationship("CHARGING_RULE", back_populates="operation_logs")
    charging_rule_id = Column(Integer, ForeignKey('charging_rule.charging_rule_id'))

class TFT_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'tft'}
    tft = relationship("TFT", back_populates="operation_logs")
    tft_id = Column(Integer, ForeignKey('tft.tft_id'))

class EIR_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'eir'}
    eir = relationship("EIR", back_populates="operation_logs")
    eir_id = Column(Integer, ForeignKey('eir.eir_id'))

class IMSI_IMEI_HISTORY_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'eir_history'}
    eir_history = relationship("IMSI_IMEI_HISTORY", back_populates="operation_logs")
    imsi_imei_history_id = Column(Integer, ForeignKey('eir_history.imsi_imei_history_id'))

class SUBSCRIBER_ATTRIBUTES_OPERATION_LOG(OPERATION_LOG_BASE):
    __mapper_args__ = {'polymorphic_identity': 'subscriber_attributes'}
    subscriber_attributes = relationship("SUBSCRIBER_ATTRIBUTES", back_populates="operation_logs")
    subscriber_attributes_id = Column(Integer, ForeignKey('subscriber_attributes.subscriber_attributes_id'))


class Database:

    def __init__(self, logTool, redisMessaging=None):
        with open("../config.yaml", 'r') as stream:
            self.config = (yaml.safe_load(stream))
        
        self.redisUseUnixSocket = self.config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = self.config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = self.config.get('redis', {}).get('host', 'localhost')
        self.redisPort = self.config.get('redis', {}).get('port', 6379)

        self.logTool = logTool
        if redisMessaging:
            self.redisMessaging = redisMessaging
        else:
            self.redisMessaging = RedisMessaging(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)

        if str(self.config['database']['db_type']) == 'postgresql':
            db_string = 'postgresql+psycopg2://' + str(self.config['database']['username']) + ':' + str(self.config['database']['password']) + '@' + str(self.config['database']['server']) + '/' + str(self.config['database']['database'])
        else:
            db_string = 'mysql://' + str(self.config['database']['username']) + ':' + str(self.config['database']['password']) + '@' + str(self.config['database']['server']) + '/' + str(self.config['database']['database'] + "?autocommit=true")

        
        self.engine = create_engine(
            db_string, 
            echo = self.config['logging'].get('sqlalchemy_sql_echo', False), 
            pool_recycle=self.config['logging'].get('sqlalchemy_pool_recycle', 5),
            pool_size=self.config['logging'].get('sqlalchemy_pool_size', 30),
            max_overflow=self.config['logging'].get('sqlalchemy_max_overflow', 0))

        # Create database if it does not exist.
        if not database_exists(self.engine.url):
            self.logTool.log(service='Database', level='debug', message="Creating database", redisClient=self.redisMessaging)
            create_database(self.engine.url)
            Base.metadata.create_all(self.engine)
        else:
            self.logTool.log(service='Database', level='debug', message="Database already created", redisClient=self.redisMessaging)

        #Load IMEI TAC database into Redis if enabled
        if ('tac_database_csv' in self.config['eir']):
            self.load_IMEI_database_into_Redis()
            self.tacData = json.loads(self.redisMessaging.getValue(key="tacDatabase"))
        else:
            self.logTool.log(service='Database', level='info', message="Not loading EIR IMEI TAC Database as Redis not enabled or TAC CSV Database not set in config", redisClient=self.redisMessaging)
            self.tacData = {}

    # Create individual tables if they do not exist.
        inspector = Inspector.from_engine(self.engine)
        for table_name in Base.metadata.tables.keys():
            if table_name not in inspector.get_table_names():
                self.logTool.log(service='Database', level='debug', message=f"Creating table {table_name}", redisClient=self.redisMessaging)
                Base.metadata.tables[table_name].create(bind=self.engine)
            else:
                self.logTool.log(service='Database', level='debug', message=f"Table {table_name} already exists", redisClient=self.redisMessaging)


    def load_IMEI_database_into_Redis(self):
        try:
            self.logTool.log(service='Database', level='info', message="Reading IMEI TAC database CSV from " + str(self.config['eir']['tac_database_csv']), redisClient=self.redisMessaging)
            csvfile = open(str(self.config['eir']['tac_database_csv']))
            self.logTool.log(service='Database', level='info', message="This may take a few seconds to buffer into Redis...", redisClient=self.redisMessaging)
        except:
            self.logTool.log(service='Database', level='error', message="Failed to read CSV file of IMEI TAC database", redisClient=self.redisMessaging)
            return
        try:
            count = 0
            tacList = {"tacList": []}
            for line in csvfile:
                line = line.replace('"', '')        #Strip excess invered commas
                line = line.replace("'", '')        #Strip excess invered commas
                line = line.rstrip()                #Strip newlines
                result = line.split(',')
                tacPrefix = result[0]
                name = result[1].lstrip()
                model = result[2].lstrip()
                
                if count == 0:
                    self.logTool.log(service='Database', level='info', message="Checking to see if entries are already present...", redisClient=self.redisMessaging)
                    redis_imei_result = self.redisMessaging.getValue(key="tacDatabase")
                    if redis_imei_result is not None:
                        if len(redis_imei_result) > 0:
                            self.logTool.log(service='Database', level='info', message="IMEI TAC Database already loaded into Redis - Skipping reading from file...", redisClient=self.redisMessaging)
                            return
                        self.logTool.log(service='Database', level='info', message="No data loaded into Redis, proceeding to load...", redisClient=self.redisMessaging)
                tacList['tacList'].append({str(tacPrefix): {'name': name, 'model': model}})
                count += 1
            self.redisMessaging.setValue(key="tacDatabase", value=json.dumps(tacList))
            self.tacData = tacList
            self.logTool.log(service='Database', level='info', message="Loaded " + str(count) + " IMEI TAC entries into Redis", redisClient=self.redisMessaging)
        except Exception as E:
            self.logTool.log(service='Database', level='error', message="Failed to load IMEI Database into Redis due to error: " + (str(E)), redisClient=self.redisMessaging)
            return

    def safe_rollback(self, session):
        try:
            if session.is_active:
                session.rollback()
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"Failed to rollback session, error: {E}", redisClient=self.redisMessaging)

    def safe_close(self, session):
        try:
            if session.is_active:
                session.close()
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"Failed to run safe_close on session, error: {E}", redisClient=self.redisMessaging)

    def sqlalchemy_type_to_json_schema_type(self, sqlalchemy_type):
        """
        Map SQLAlchemy types to JSON Schema types.
        """
        if isinstance(sqlalchemy_type, Integer):
            return "integer"
        elif isinstance(sqlalchemy_type, String):
            return "string"
        elif isinstance(sqlalchemy_type, Boolean):
            return "boolean"
        elif isinstance(sqlalchemy_type, DateTime):
            return "string"
        elif isinstance(sqlalchemy_type, Float):
            return "number"
        else:
            return "string"  # Default to string for unsupported types.

    def generate_json_schema(self, model_class, required=None):
        properties = {}
        required = required or []

        for column in model_class.__table__.columns:
            prop_type = self.sqlalchemy_type_to_json_schema_type(column.type)
            prop_dict = {
                "type": prop_type,
                "description": column.doc
            }
            if prop_type == "string":
                if hasattr(column.type, 'length'):
                    prop_dict["maxLength"] = column.type.length
            if isinstance(column.type, DateTime):
                prop_dict["format"] = "date-time"
            if not column.nullable:
                required.append(column.name)
            properties[column.name] = prop_dict

        return {"type": "object", "title" : str(model_class.__name__), "properties": properties, "required": required}

    def update_old_record(self, session, operation_log):
        oldest_log = session.query(OPERATION_LOG_BASE).order_by(OPERATION_LOG_BASE.timestamp.asc()).first()
        if oldest_log is not None:
            for attr in class_mapper(oldest_log.__class__).column_attrs:
                if attr.key != 'id' and hasattr(operation_log, attr.key):
                    setattr(oldest_log, attr.key, getattr(operation_log, attr.key))
            oldest_log.timestamp = datetime.datetime.now(tz=timezone.utc)
            session.flush()
        else:
            raise ValueError("Unable to find record to update")

    def log_change(self, session, item_id, operation, changes, table_name, operation_id, generated_id=None):
        # We don't want to log rollback operations
        if session.info.get("operation") == 'ROLLBACK':
            return
        max_records = 1000
        count = session.query(OPERATION_LOG_BASE).count()

        # Combine all changes into a single string with their types
        changes_string = '\r\n\r\n'.join(f"{column_name}: [{type(old_value).__name__}] {old_value} ----> [{type(new_value).__name__}] {new_value}" for column_name, old_value, new_value in changes)

        change = OPERATION_LOG_BASE(
            item_id=item_id or generated_id,
            operation_id=operation_id,
            operation=operation,
            last_modified=datetime.datetime.now(tz=timezone.utc),
            changes=changes_string,
            table_name=table_name
        )

        if count >= max_records:
            self.update_old_record(session, change)
        else:
            try:
                session.add(change)
                session.flush()
            except Exception as E:
                self.logTool.log(service='Database', level='error', message="Failed to commit changelog, error: " + str(E), redisClient=self.redisMessaging)
                self.safe_rollback(session)
                self.safe_close(session)
                raise ValueError(E)
        return operation_id


    def log_changes_before_commit(self, session):

        operation_id = session.info.get("operation_id", None) or str(uuid.uuid4())
        if session.info.get("operation") == 'ROLLBACK':
            return

        changelog_pending = any(isinstance(obj, OPERATION_LOG_BASE) for obj in session.new)
        if changelog_pending:
            return  # Skip if there are pending OPERATION_LOG_BASE objects

        for state, operation in [
            (session.new, 'INSERT'),
            (session.dirty, 'UPDATE'),
            (session.deleted, 'DELETE')
        ]:
            for obj in state:
                if isinstance(obj, OPERATION_LOG_BASE):
                    continue  # Skip change log entries

                item_id = getattr(obj, list(obj.__table__.primary_key.columns.keys())[0])
                generated_id = None

                #Avoid logging rollback operations
                if operation == 'ROLLBACK':
                    return

                # Flush the session to generate primary key for new objects
                if operation == 'INSERT':
                    session.flush()

                if operation == 'UPDATE':
                    changes = []
                    for attr in class_mapper(obj.__class__).column_attrs:
                        hist = get_history(obj, attr.key)
                        self.logTool.log(service='Database', level='debug', message=f"History {hist}", redisClient=self.redisMessaging)
                        if hist.has_changes() and hist.added and hist.deleted:
                            old_value, new_value = hist.deleted[0], hist.added[0]
                            self.logTool.log(service='Database', level='debug', message=f"Old Value {old_value}", redisClient=self.redisMessaging)
                            self.logTool.log(service='Database', level='debug', message=f"New Value {new_value}", redisClient=self.redisMessaging)
                            changes.append((attr.key, old_value, new_value))
                            continue

                    if not changes:
                        continue

                    operation_id = self.log_change(session, item_id, operation, changes, obj.__table__.name, operation_id)

                elif operation in ['INSERT', 'DELETE']:
                    changes = []
                    for column in obj.__table__.columns:
                        column_name = column.name
                        value = getattr(obj, column_name)
                        if operation == 'INSERT':
                            old_value, new_value = None, value
                            if item_id is None:
                                generated_id = getattr(obj, list(obj.__table__.primary_key.columns.keys())[0])
                        elif operation == 'DELETE':
                            old_value, new_value = value, None
                        changes.append((column_name, old_value, new_value))
                    operation_id = self.log_change(session, item_id, operation, changes, obj.__table__.name, operation_id, generated_id)

    def get_class_by_tablename(self, base, tablename):
        """
        Returns a class object based on the given tablename.

        :param base: Base class of SQLAlchemy models
        :param tablename: Name of the table to retrieve the class for
        :return: Class object or None if not found
        """
        for mapper in base.registry.mappers:
            cls = mapper.class_
            if hasattr(cls, '__tablename__') and cls.__tablename__ == tablename:
                return cls
        return None

    def str_to_type(self, type_str, value_str):
        if type_str == 'int':
            return int(value_str)
        elif type_str == 'float':
            return float(value_str)
        elif type_str == 'str':
            return value_str
        elif type_str == 'bool':
            return value_str == 'True'
        elif type_str == 'NoneType':
            return None
        else:
            raise ValueError(f'Cannot convert to type: {type_str}')


    def rollback_last_change(self, existingSession=None):
        if not existingSession:
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            session = Session()
        else:
            session = existingSession

        try:
            # Get the most recent operation
            last_operation = session.query(OPERATION_LOG_BASE).order_by(desc(OPERATION_LOG_BASE.timestamp)).first()

            if last_operation is None:
                return "No operations to roll back."

            rollback_messages = []
            operation_id = str(uuid.uuid4())

            target_class = self.get_class_by_tablename(Base, last_operation.table_name)
            if not target_class:
                return f"Error: Could not find table {last_operation.table_name}"

            primary_key_col = target_class.__mapper__.primary_key[0].key
            filter_by_kwargs = {primary_key_col: last_operation.item_id}
            target_item = session.query(target_class).filter_by(**filter_by_kwargs).one_or_none()

            if last_operation.operation == 'UPDATE':
                if not target_item:
                    return f"Error: Could not find item with ID {last_operation.item_id} in {last_operation.table_name.upper()} table"

                # Split the changes string into separate changes
                changes = last_operation.changes.split('\r\n\r\n')
                for change in changes:
                    column_name, old_new_values = change.split(": ", 1)
                    old_value_str, new_value_str = old_new_values.split(" ----> ", 1)

                    # Extract type and value
                    old_type_str, old_value_repr = old_value_str[1:-1].split("] ", 1)
                    old_value = self.str_to_type(old_type_str, old_value_repr)

                    # Revert the change
                    setattr(target_item, column_name, old_value)

                rollback_message = (
                    f"Rolled back '{last_operation.operation}' operation on {last_operation.table_name.upper()} table (ID: {last_operation.item_id}): Reverted changes"
                )

            elif last_operation.operation == 'INSERT':
                if target_item:
                    session.delete(target_item)

                rollback_message = (
                    f"Rolled back '{last_operation.operation}' operation on {last_operation.table_name.upper()} table (ID: {last_operation.item_id}): Deleted item"
                )

            elif last_operation.operation == 'DELETE':
                # Aggregate old values of all columns into a single dictionary
                old_values_dict = {}
                # Split the changes string into separate changes
                changes = last_operation.changes.split('\r\n\r\n')
                for change in changes:
                    column_name, old_new_values = change.split(": ", 1)
                    old_value_str, new_value_str = old_new_values.split(" ----> ", 1)

                    # Extract type and value
                    old_type_str, old_value_repr = old_value_str[1:].split("] ", 1)
                    self.logTool.log(service='Database', level='error', message=f"running str_to_type for: {str(old_type_str)}, {str(old_value_repr)}", redisClient=self.redisMessaging)
                    old_value = self.str_to_type(old_type_str, old_value_repr)

                    old_values_dict[column_name] = old_value
                self.logTool.log(service='Database', level='error', message="old_value_dict: " + str(old_values_dict), redisClient=self.redisMessaging)

                if not target_item:
                    try:
                        # Create the target item using the aggregated old values
                        target_item = target_class(**old_values_dict)
                        session.add(target_item)
                    except Exception as e:
                        return f"Error: Failed to recreate item with ID {last_operation.item_id} in {last_operation.table_name.upper()} table - {str(e)}"

                rollback_message = (
                    f"Rolled back '{last_operation.operation}' operation on {last_operation.table_name.upper()} table (ID: {last_operation.item_id}): Re-inserted item"
                )

            else:
                return f"Error: Unknown operation {last_operation.operation}"

            try:
                session.commit()
                self.safe_close(session)
            except Exception as E:
                self.logTool.log(service='Database', level='error', message="rollback_last_change error: " + str(E), redisClient=self.redisMessaging)
                self.safe_rollback(session)
                self.safe_close(session)
                raise ValueError(E)

            return f"Rolled back operation with operation_id: {operation_id}\n" + "\n".join(rollback_messages)

        except Exception as E:
            self.logTool.log(service='Database', level='error', message="rollback_last_change error: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)

    def rollback_change_by_operation_id(self, operation_id, existingSession=None):
        if not existingSession:
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            session = Session()
        else:
            session = existingSession

        try:
            # Get the most recent operation
            last_operation = session.query(OPERATION_LOG_BASE).filter(OPERATION_LOG_BASE.operation_id == operation_id).order_by(desc(OPERATION_LOG_BASE.timestamp)).first()

            if last_operation is None:
                return "No operation to roll back."

            rollback_messages = []
            operation_id = str(uuid.uuid4())

            target_class = self.get_class_by_tablename(Base, last_operation.table_name)
            if not target_class:
                return f"Error: Could not find table {last_operation.table_name}"

            primary_key_col = target_class.__mapper__.primary_key[0].key
            filter_by_kwargs = {primary_key_col: last_operation.item_id}
            target_item = session.query(target_class).filter_by(**filter_by_kwargs).one_or_none()

            if last_operation.operation == 'UPDATE':
                if not target_item:
                    return f"Error: Could not find item with ID {last_operation.item_id} in {last_operation.table_name.upper()} table"

                # Split the changes string into separate changes
                changes = last_operation.changes.split('\r\n\r\n')
                for change in changes:
                    column_name, old_new_values = change.split(": ", 1)
                    old_value_str, new_value_str = old_new_values.split(" ----> ", 1)

                    # Extract type and value
                    old_type_str, old_value_repr = old_value_str[1:-1].split("] ", 1)
                    old_value = self.str_to_type(old_type_str, old_value_repr)

                    # Revert the change
                    setattr(target_item, column_name, old_value)

                rollback_message = (
                    f"Rolled back '{last_operation.operation}' operation on {last_operation.table_name.upper()} table (ID: {last_operation.item_id}): Reverted changes"
                )

            elif last_operation.operation == 'INSERT':
                if target_item:
                    session.delete(target_item)

                rollback_message = (
                    f"Rolled back '{last_operation.operation}' operation on {last_operation.table_name.upper()} table (ID: {last_operation.item_id}): Deleted item"
                )

            elif last_operation.operation == 'DELETE':
                # Aggregate old values of all columns into a single dictionary
                old_values_dict = {}
                # Split the changes string into separate changes
                changes = last_operation.changes.split('\r\n\r\n')
                for change in changes:
                    column_name, old_new_values = change.split(": ", 1)
                    old_value_str, new_value_str = old_new_values.split(" ----> ", 1)

                    # Extract type and value
                    old_type_str, old_value_repr = old_value_str[1:].split("] ", 1)
                    self.logTool.log(service='Database', level='error', message=f"running str_to_type for: {str(old_type_str)}, {str(old_value_repr)}", redisClient=self.redisMessaging)
                    old_value = self.str_to_type(old_type_str, old_value_repr)

                    old_values_dict[column_name] = old_value
                self.logTool.log(service='Database', level='error', message="old_value_dict: " + str(old_values_dict), redisClient=self.redisMessaging)

                if not target_item:
                    try:
                        # Create the target item using the aggregated old values
                        target_item = target_class(**old_values_dict)
                        session.add(target_item)
                    except Exception as e:
                        return f"Error: Failed to recreate item with ID {last_operation.item_id} in {last_operation.table_name.upper()} table - {str(e)}"

                rollback_message = (
                    f"Rolled back '{last_operation.operation}' operation on {last_operation.table_name.upper()} table (ID: {last_operation.item_id}): Re-inserted item"
                )

            else:
                return f"Error: Unknown operation {last_operation.operation}"

            try:
                session.commit()
                self.safe_close(session)
            except Exception as E:
                self.logTool.log(service='Database', level='error', message="rollback_last_change error: " + str(E), redisClient=self.redisMessaging)
                self.safe_rollback(session)
                self.safe_close(session)
                raise ValueError(E)

            return f"Rolled back operation with operation_id: {operation_id}\n" + "\n".join(rollback_messages)

        except Exception as E:
            self.logTool.log(service='Database', level='error', message="rollback_last_change error: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)

    def get_all_operation_logs(self, page=0, page_size=100, existingSession=None):
        if not existingSession:
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            session = Session()
        else:
            session = existingSession

        try:
            # Get all distinct operation_ids ordered by max timestamp (descending order)
            operation_ids = session.query(OPERATION_LOG_BASE.operation_id).group_by(OPERATION_LOG_BASE.operation_id).order_by(desc(func.max(OPERATION_LOG_BASE.timestamp)))

            operation_ids = operation_ids.limit(page_size).offset(page * page_size)

            operation_ids = operation_ids.all()

            all_operations = []

            for operation_id in operation_ids:
                operation_log = session.query(OPERATION_LOG_BASE).filter(OPERATION_LOG_BASE.operation_id == operation_id[0]).order_by(OPERATION_LOG_BASE.id.asc()).first()

                if operation_log is not None:
                    # Convert the object to dictionary
                    obj_dict = operation_log.__dict__
                    obj_dict.pop('_sa_instance_state')
                    sanitized_obj_dict = self.Sanitize_Datetime(obj_dict)
                    all_operations.append(sanitized_obj_dict)

            self.safe_close(session)
            return all_operations
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"get_all_operation_logs error: {E}", redisClient=self.redisMessaging)
            self.logTool.log(service='Database', level='error', message=E, redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)

    def get_all_operation_logs_by_table(self, table_name, page=0, page_size=100, existingSession=None):
        if not existingSession:
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            session = Session()
        else:
            session = existingSession

        try:
            # Get all distinct operation_ids ordered by max timestamp (descending order)
            operation_ids = session.query(OPERATION_LOG_BASE.operation_id).filter(OPERATION_LOG_BASE.table_name == table_name).group_by(OPERATION_LOG_BASE.operation_id).order_by(desc(func.max(OPERATION_LOG_BASE.timestamp)))

            operation_ids = operation_ids.limit(page_size).offset(page * page_size)

            operation_ids = operation_ids.all()

            all_operations = []

            for operation_id in operation_ids:
                operation_log = session.query(OPERATION_LOG_BASE).filter(OPERATION_LOG_BASE.operation_id == operation_id[0]).order_by(OPERATION_LOG_BASE.id.asc()).first()

                if operation_log is not None:
                    # Convert the object to dictionary
                    obj_dict = operation_log.__dict__
                    obj_dict.pop('_sa_instance_state')
                    sanitized_obj_dict = self.Sanitize_Datetime(obj_dict)
                    all_operations.append(sanitized_obj_dict)

            self.safe_close(session)
            return all_operations
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"get_all_operation_logs_by_table error: {E}", redisClient=self.redisMessaging)
            self.logTool.log(service='Database', level='error', message=E, redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)

    def get_last_operation_log(self, existingSession=None):
        if not existingSession:
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            session = Session()
        else:
            session = existingSession

        try:
            # Get the top 100 records ordered by timestamp (descending order)
            top_100_records = session.query(OPERATION_LOG_BASE).order_by(desc(OPERATION_LOG_BASE.timestamp)).limit(100)

            # Get the most recent operation_id
            most_recent_operation_log = top_100_records.first()

            # Convert the object to dictionary
            if most_recent_operation_log is not None:
                obj_dict = most_recent_operation_log.__dict__
                obj_dict.pop('_sa_instance_state')
                sanitized_obj_dict = self.Sanitize_Datetime(obj_dict)
                return sanitized_obj_dict

            self.safe_close(session)
            return None
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"get_last_operation_log error: {E}", redisClient=self.redisMessaging)
            self.logTool.log(service='Database', level='error', message=E, redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)

    def handleGeored(self, jsonData, operation: str="PATCH", asymmetric: bool=False, asymmetricUrls: list=[]) -> bool:
        """
        Validate the request, check configuration and queue the geored message.
        Asymmetric geored is supported (where one or more specific or foreign geored endpoints are specified).
        """
        try:
            operation = operation.upper()
            if operation not in ['PUT', 'PATCH', 'DELETE']:
                self.logTool.log(service='Database', level='warning', message="Failed to send Geored message invalid operation type, received: " + str(operation), redisClient=self.redisMessaging)
                return
            georedDict = {}
            if self.config.get('geored', {}).get('enabled', False):
                if self.config.get('geored', {}).get('endpoints', []) is not None:
                    if len(self.config.get('geored', {}).get('endpoints', [])) > 0:
                        georedDict['body'] = jsonData
                        georedDict['operation'] = operation
                        georedDict['timestamp'] = time.time_ns()
                        self.redisMessaging.sendMessage(queue=f'geored', message=json.dumps(georedDict), queueExpiry=120)
                if asymmetric:
                    if len(asymmetricUrls) > 0:
                        georedDict['body'] = jsonData
                        georedDict['operation'] = operation
                        georedDict['timestamp'] = time.time_ns()
                        georedDict['urls'] = asymmetricUrls
                        self.redisMessaging.sendMessage(queue=f'asymmetric-geored', message=json.dumps(georedDict), queueExpiry=120)
            return True

        except Exception as E:
            self.logTool.log(service='Database', level='warning', message="Failed to send Geored message due to error: " + str(E), redisClient=self.redisMessaging)
            return False

    def handleWebhook(self, objectData, operation: str="PATCH"):
        webhooksEnabled = self.config.get('webhooks', {}).get('enabled', False)
        endpointList = self.config.get('webhooks', {}).get('endpoints', [])
        webhook = {}

        if not webhooksEnabled:
            return False
        
        if endpointList is None:
            return False
        
        if not len (endpointList) > 0:
            self.logTool.log(service='Database', level='error', message="Webhooks enabled, but endpoints are missing.", redisClient=self.redisMessaging)
            return False

        webhookHeaders = {'Content-Type': 'application/json', 'Referer': socket.gethostname()}

        webhook['body'] = self.Sanitize_Datetime(objectData)
        webhook['headers'] = webhookHeaders
        webhook['operation'] = operation
        webhook['timestamp'] = time.time_ns()
        self.redisMessaging.sendMessage(queue=f'webhook', message=json.dumps(webhook), queueExpiry=120)
        return True

    def Sanitize_Datetime(self, result):
        for keys in result:
            if "timestamp" in keys:
                if result[keys] == None:
                    continue
                else:
                    self.logTool.log(service='Database', level='debug', message="Key " + str(keys) + " is type DateTime with value: " + str(result[keys]) + " - Formatting to String", redisClient=self.redisMessaging)
                    try:
                        result[keys] = result[keys].strftime('%Y-%m-%dT%H:%M:%SZ')
                    except Exception as e:
                        result[keys] = str(result[keys])
        return result

    def Sanitize_Keys(self, result):
        names_to_strip = ['opc', 'ki', 'des', 'kid', 'psk', 'adm1']
        for name_to_strip in names_to_strip:
            try:
                result.pop(name_to_strip)
            except:
                pass
        return result 

    def GetObj(self, obj_type, obj_id=None, page=None, page_size=None):
        self.logTool.log(service='Database', level='debug', message="Called GetObj for type " + str(obj_type), redisClient=self.redisMessaging)

        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        session = Session()

        try:
            if obj_id is not None:
                result = session.query(obj_type).get(obj_id)
                if result is None:
                    raise ValueError(f"No {obj_type} found with id {obj_id}")

                result = result.__dict__
                result.pop('_sa_instance_state')
                result = self.Sanitize_Datetime(result)
            elif page is not None and page_size is not None:
                if page < 1 or page_size < 1:
                    raise ValueError("page and page_size should be positive integers")

                offset = (page - 1) * page_size
                results = (
                    session.query(obj_type)
                    .order_by(obj_type.id)  # Assuming obj_type has an attribute 'id'
                    .offset(offset)
                    .limit(page_size)
                    .all()
                )

                result = []
                for item in results:
                    item_dict = item.__dict__
                    item_dict.pop('_sa_instance_state')
                    result.append(self.Sanitize_Datetime(item_dict))
            else:
                raise ValueError("Provide either obj_id or both page and page_size")

        except Exception as E:
            self.logTool.log(service='Database', level='error', message="Failed to query, error: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)

        self.safe_close(session)
        return result

    def GetAll(self, obj_type):
        self.logTool.log(service='Database', level='debug', message="Called GetAll for type " + str(obj_type), redisClient=self.redisMessaging)

        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind = self.engine)
        session = Session()
        final_result_list = []

        try:
            result = session.query(obj_type)
        except Exception as E:
            self.logTool.log(service='Database', level='error', message="Failed to query, error: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)    
        
        for record in result:
            record = record.__dict__
            record.pop('_sa_instance_state')
            record = self.Sanitize_Datetime(record)
            final_result_list.append(record)

        self.safe_close(session)
        return final_result_list

    def getAllPaginated(self, obj_type, page=0, page_size=0, existingSession=None):
        self.logTool.log(service='Database', level='debug', message="Called getAllPaginated for type " + str(obj_type), redisClient=self.redisMessaging)

        if not existingSession:
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            session = Session()
        else:
            session = existingSession

        final_result_list = []

        try:
            # Query object type
            result = session.query(obj_type)

            # Apply pagination
            if page_size != 0:
                result = result.limit(page_size).offset(page * page_size)
            
            result = result.all()

            for record in result:
                record = record.__dict__
                record.pop('_sa_instance_state')
                record = self.Sanitize_Datetime(record)
                final_result_list.append(record)
                
            self.safe_close(session)
            return final_result_list

        except Exception as E:
            self.logTool.log(service='Database', level='error', message="Failed to query, error: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)


    def GetAllByTable(self, obj_type, table):
        self.logTool.log(service='Database', level='debug', message=f"Called GetAll for type {str(obj_type)} and table {table}", redisClient=self.redisMessaging)

        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind = self.engine)
        session = Session()
        final_result_list = []

        try:
            result = session.query(obj_type).filter_by(table_name=str(table))
        except Exception as E:
            self.logTool.log(service='Database', level='error', message="Failed to query, error: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)    
        
        for record in result:
            record = record.__dict__
            record.pop('_sa_instance_state')
            record = self.Sanitize_Datetime(record)
            final_result_list.append(record)

        self.safe_close(session)
        return final_result_list

    def UpdateObj(self, obj_type, json_data, obj_id, disable_logging=False, operation_id=None):
        self.logTool.log(service='Database', level='debug', message=f"Called UpdateObj() for type {obj_type} id {obj_id} with JSON data: {json_data} and operation_id: {operation_id}", redisClient=self.redisMessaging)
        Session = sessionmaker(bind=self.engine)
        session = Session()
        obj_type_str = str(obj_type.__table__.name).upper()
        self.logTool.log(service='Database', level='debug', message=f"obj_type_str is {obj_type_str}", redisClient=self.redisMessaging)
        filter_input = eval(obj_type_str + "." + obj_type_str.lower() + "_id==obj_id")
        try:
            obj = session.query(obj_type).filter(filter_input).one()
            for key, value in json_data.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)
                    setattr(obj, "last_modified", datetime.datetime.now(tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z')
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"Failed to query or update object, error: {E}", redisClient=self.redisMessaging)
            raise ValueError(E)
        try:
                session.info["operation_id"] = operation_id  # Pass the operation id
                try:
                    if not disable_logging:
                        self.log_changes_before_commit(session)
                    objectData = self.GetObj(obj_type, obj_id)
                    session.commit()
                    self.handleWebhook(objectData, 'PATCH')
                except Exception as E:
                    self.logTool.log(service='Database', level='error', message=f"Failed to commit session, error: {E}", redisClient=self.redisMessaging)
                    self.safe_rollback(session)
                    raise ValueError(E)
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"Exception in UpdateObj, error: {E}", redisClient=self.redisMessaging)
            raise ValueError(E)
        finally:
            self.safe_close(session)

        return self.GetObj(obj_type, obj_id)

    def DeleteObj(self, obj_type, obj_id, disable_logging=False, operation_id=None):
        self.logTool.log(service='Database', level='debug', message=f"Called DeleteObj for type {obj_type} with id {obj_id}", redisClient=self.redisMessaging)

        Session = sessionmaker(bind=self.engine)
        session = Session()

        try:
            res = session.query(obj_type).get(obj_id)
            if res is None:
                raise ValueError("The specified row does not exist")
            objectData = self.GetObj(obj_type, obj_id)
            session.delete(res)
            session.info["operation_id"] = operation_id  # Pass the operation id
            try:
                if not disable_logging:
                    self.log_changes_before_commit(session)
                session.commit()
                self.handleWebhook(objectData, 'DELETE')
            except Exception as E:
                self.logTool.log(service='Database', level='error', message=f"Failed to commit session, error: {E}", redisClient=self.redisMessaging)
                self.safe_rollback(session)
                raise ValueError(E)

        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"Exception in DeleteObj, error: {E}", redisClient=self.redisMessaging)
            raise ValueError(E)
        finally:
            self.safe_close(session)

        return {'Result': 'OK'}


    def CreateObj(self, obj_type, json_data, disable_logging=False, operation_id=None):
        self.logTool.log(service='Database', level='debug', message="Called CreateObj to create " + str(obj_type) + " with value: " + str(json_data), redisClient=self.redisMessaging)
        last_modified_value = datetime.datetime.now(tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        json_data["last_modified"] = last_modified_value  # set last_modified value in json_data
        newObj = obj_type(**json_data)
        Session = sessionmaker(bind=self.engine)
        session = Session()

        session.add(newObj)
        try:
            session.info["operation_id"] = operation_id  # Pass the operation id
            try:
                if not disable_logging:
                    self.log_changes_before_commit(session)
                session.commit()
            except Exception as E:
                self.logTool.log(service='Database', level='error', message=f"Failed to commit session, error: {E}", redisClient=self.redisMessaging)
                self.safe_rollback(session)
                raise ValueError(E)
            session.refresh(newObj)
            result = newObj.__dict__
            result.pop('_sa_instance_state')
            self.handleWebhook(result, 'PUT')
            return result
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"Exception in CreateObj, error: {E}", redisClient=self.redisMessaging)
            raise ValueError(E)
        finally:
            self.safe_close(session)

    def Generate_JSON_Model_for_Flask(self, obj_type):
        self.logTool.log(service='Database', level='debug', message="Generating JSON model for Flask for object type: " + str(obj_type), redisClient=self.redisMessaging)

        dictty = dict(self.generate_json_schema(obj_type))
        # pprint.pprint(dictty)


        #dictty['properties'] = dict(dictty['properties'])

        # Exclude 'table_name' column from the properties
        if 'properties' in dictty:
            dictty['properties'].pop('discriminator', None)
            dictty['properties'].pop('last_modified', None)
            

        # Set the ID Object to not required
        obj_type_str = str(dictty['title']).lower()
        dictty['required'].remove(obj_type_str + '_id')

        return dictty

    def Get_AuC(self, **kwargs):
        #Get AuC data by IMSI or ICCID

        Session = sessionmaker(bind = self.engine)
        session = Session()

        if 'iccid' in kwargs:
            self.logTool.log(service='Database', level='debug', message="Get_AuC for iccid " + str(kwargs['iccid']), redisClient=self.redisMessaging)
            try:
                result = session.query(AUC).filter_by(iccid=str(kwargs['iccid'])).one()
            except Exception as E:
                self.safe_close(session)
                raise ValueError(E)
        elif 'imsi' in kwargs:
            self.logTool.log(service='Database', level='debug', message="Get_AuC for imsi " + str(kwargs['imsi']), redisClient=self.redisMessaging)
            try:
                result = session.query(AUC).filter_by(imsi=str(kwargs['imsi'])).one()
            except Exception as E:
                self.safe_close(session)
                raise ValueError(E)

        result = result.__dict__
        result = self.Sanitize_Datetime(result)
        result.pop('_sa_instance_state')

        self.logTool.log(service='Database', level='debug', message="Got back result: " + str(result), redisClient=self.redisMessaging)
        self.safe_close(session)
        return result

    def Get_IMS_Subscriber(self, **kwargs):
        #Get subscriber by IMSI or MSISDN
        Session = sessionmaker(bind = self.engine)
        session = Session()
        if 'msisdn' in kwargs:
            self.logTool.log(service='Database', level='debug', message="Get_IMS_Subscriber for msisdn " + str(kwargs['msisdn']), redisClient=self.redisMessaging)
            try:
                result = session.query(IMS_SUBSCRIBER).filter_by(msisdn=str(kwargs['msisdn'])).one()
            except Exception as E:
                self.safe_close(session)
                raise ValueError(E)
        elif 'imsi' in kwargs:
            self.logTool.log(service='Database', level='debug', message="Get_IMS_Subscriber for imsi " + str(kwargs['imsi']), redisClient=self.redisMessaging)
            try:
                result = session.query(IMS_SUBSCRIBER).filter_by(imsi=str(kwargs['imsi'])).one()
            except Exception as E:
                self.safe_close(session)
                raise ValueError(E)
        self.logTool.log(service='Database', level='debug', message="Converting result to dict", redisClient=self.redisMessaging)
        result = result.__dict__
        try:
            result.pop('_sa_instance_state')
        except:
            pass
        result = self.Sanitize_Datetime(result)
        self.logTool.log(service='Database', level='debug', message="Returning IMS Subscriber Data: " + str(result), redisClient=self.redisMessaging)
        self.safe_close(session)
        return result

    def Get_Subscriber(self, **kwargs):
        #Get subscriber by IMSI or MSISDN

        Session = sessionmaker(bind = self.engine)
        session = Session()

        if 'subscriber_id' in kwargs:
            self.logTool.log(service='Database', level='debug', message="Get_Subscriber for id " + str(kwargs['subscriber_id']), redisClient=self.redisMessaging)
            try:
                result = session.query(SUBSCRIBER).filter_by(subscriber_id=int(kwargs['subscriber_id'])).one()
            except Exception as E:
                self.safe_close(session)
                raise ValueError(E)
        elif 'msisdn' in kwargs:
            self.logTool.log(service='Database', level='debug', message="Get_Subscriber for msisdn " + str(kwargs['msisdn']), redisClient=self.redisMessaging)
            try:
                result = session.query(SUBSCRIBER).filter_by(msisdn=str(kwargs['msisdn'])).one()
            except Exception as E:
                self.safe_close(session)
                raise ValueError(E)
        elif 'imsi' in kwargs:
            self.logTool.log(service='Database', level='debug', message="Get_Subscriber for imsi " + str(kwargs['imsi']), redisClient=self.redisMessaging)
            try:
                result = session.query(SUBSCRIBER).filter_by(imsi=str(kwargs['imsi'])).one()
            except Exception as E:
                self.safe_close(session)
                raise ValueError(E)

        result = result.__dict__
        result = self.Sanitize_Datetime(result)
        result.pop('_sa_instance_state')
        
        if 'get_attributes' in kwargs:
            if kwargs['get_attributes'] == True:
                attributes = self.Get_Subscriber_Attributes(result['subscriber_id'])
                result['attributes'] = attributes

        self.logTool.log(service='Database', level='debug', message="Got back result: " + str(result), redisClient=self.redisMessaging)
        self.safe_close(session)
        return result

    def Get_Subscribers_By_Pcscf(self, pcscf: str):
        Session = sessionmaker(bind = self.engine)
        session = Session()
        self.logTool.log(service='Database', level='debug', message=f"[database.py] [Get_Subscribers_By_Pcscf] Get_Subscribers_By_Pcscf for PCSCF: {pcscf}", redisClient=self.redisMessaging)
        try:
            result = session.query(IMS_SUBSCRIBER).filter_by(pcscf=pcscf).all()
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        returnList = []
        for item in result:
            try:
                returnList.append(item.__dict__)
            except Exception as e:
                self.logTool.log(service='Database', level='warning', message=f"[database.py] [Get_Subscribers_By_Pcscf] Error getting ims_subscriber: {traceback.format_exc()}", redisClient=self.redisMessaging)
                pass
        for item in returnList:
            try:
                item.pop('_sa_instance_state')
            except Exception as e:
                pass
        self.safe_close(session)
        return returnList

    def Get_SUBSCRIBER_ROUTING(self, subscriber_id, apn_id):
        Session = sessionmaker(bind = self.engine)
        session = Session()

        self.logTool.log(service='Database', level='debug', message="Get_SUBSCRIBER_ROUTING for subscriber_id " + str(subscriber_id) + " and apn_id " + str(apn_id), redisClient=self.redisMessaging)
        try:
            result = session.query(SUBSCRIBER_ROUTING).filter_by(subscriber_id=subscriber_id, apn_id=apn_id).one()
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)

        result = result.__dict__
        result = self.Sanitize_Datetime(result)
        result.pop('_sa_instance_state')

        self.logTool.log(service='Database', level='debug', message="Got back result: " + str(result), redisClient=self.redisMessaging)
        self.safe_close(session)
        return result

    def Get_Subscriber_Attributes(self, subscriber_id):
        #Get subscriber attributes

        Session = sessionmaker(bind = self.engine)
        session = Session()

        self.logTool.log(service='Database', level='debug', message="Get_Subscriber_Attributes for subscriber_id " + str(subscriber_id), redisClient=self.redisMessaging)
        try:
            result = session.query(SUBSCRIBER_ATTRIBUTES).filter_by(subscriber_id=subscriber_id)
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        final_res = []
        for record in result:
            result = record.__dict__
            result = self.Sanitize_Datetime(result)
            result.pop('_sa_instance_state')
            final_res.append(result)
        self.logTool.log(service='Database', level='debug', message="Got back result: " + str(final_res), redisClient=self.redisMessaging)
        self.safe_close(session)
        return final_res


    def Get_Served_Subscribers(self, get_local_users_only=False):
        self.logTool.log(service='Database', level='debug', message="Getting all subscribers served by this HSS", redisClient=self.redisMessaging)

        Session = sessionmaker(bind = self.engine)
        session = Session()

        Served_Subs = {}
        try:
            results = session.query(SUBSCRIBER).filter(SUBSCRIBER.serving_mme.isnot(None))
            for result in results:
                result = result.__dict__
                self.logTool.log(service='Database', level='debug', message="Result: " + str(result) + " type: " + str(type(result)), redisClient=self.redisMessaging)
                result = self.Sanitize_Datetime(result)
                result.pop('_sa_instance_state')

                if get_local_users_only == True:
                    self.logTool.log(service='Database', level='debug', message="Filtering to locally served IMS Subs only", redisClient=self.redisMessaging)
                    try:
                        serving_hss = result['serving_mme_peer'].split(';')[1]
                        self.logTool.log(service='Database', level='debug', message="Serving HSS: " + str(serving_hss) + " and this is: " + str(self.config['hss']['OriginHost']), redisClient=self.redisMessaging)
                        if serving_hss == self.config['hss']['OriginHost']:
                            self.logTool.log(service='Database', level='debug', message="Serving HSS matches local HSS", redisClient=self.redisMessaging)
                            Served_Subs[result['imsi']] = {}
                            Served_Subs[result['imsi']] = result
                            #self.logTool.log(service='Database', level='debug', message="Processed result", redisClient=self.redisMessaging)
                            continue
                        else:
                            self.logTool.log(service='Database', level='debug', message="Sub is served by remote HSS: " + str(serving_hss), redisClient=self.redisMessaging)
                    except Exception as E:
                        self.logTool.log(service='Database', level='debug', message="Error in filtering Get_Served_Subscribers to local peer only: " + str(E), redisClient=self.redisMessaging)
                        continue
                else:
                    Served_Subs[result['imsi']] = result
                    self.logTool.log(service='Database', level='debug', message="Processed result", redisClient=self.redisMessaging)


        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        self.logTool.log(service='Database', level='debug', message="Final Served_Subs: " + str(Served_Subs), redisClient=self.redisMessaging)
        self.safe_close(session)
        return Served_Subs


    def Get_Served_IMS_Subscribers(self, get_local_users_only=False):
        self.logTool.log(service='Database', level='debug', message="Getting all subscribers served by this IMS-HSS", redisClient=self.redisMessaging)
        Session = sessionmaker(bind=self.engine)
        session = Session()

        Served_Subs = {}
        try:
            
            results = session.query(IMS_SUBSCRIBER).filter(
                IMS_SUBSCRIBER.scscf.isnot(None))
            for result in results:
                result = result.__dict__
                self.logTool.log(service='Database', level='debug', message="Result: " + str(result, redisClient=self.redisMessaging) +
                            " type: " + str(type(result)))
                result = self.Sanitize_Datetime(result)
                result.pop('_sa_instance_state')
                if get_local_users_only == True:
                    self.logTool.log(service='Database', level='debug', message="Filtering Get_Served_IMS_Subscribers to locally served IMS Subs only", redisClient=self.redisMessaging)
                    try:
                        serving_ims_hss = result['scscf_peer'].split(';')[1]
                        self.logTool.log(service='Database', level='debug', message="Serving IMS-HSS: " + str(serving_ims_hss) + " and this is: " + str(self.config['hss']['OriginHost']), redisClient=self.redisMessaging)
                        if serving_ims_hss == self.config['hss']['OriginHost']:
                            self.logTool.log(service='Database', level='debug', message="Serving IMS-HSS matches local HSS for " + str(result['imsi']), redisClient=self.redisMessaging)
                            Served_Subs[result['imsi']] = {}
                            Served_Subs[result['imsi']] = result
                            self.logTool.log(service='Database', level='debug', message="Processed result", redisClient=self.redisMessaging)
                            continue
                        else:
                            self.logTool.log(service='Database', level='debug', message="Sub is served by remote IMS-HSS: " + str(serving_ims_hss), redisClient=self.redisMessaging)
                    except Exception as E:
                        self.logTool.log(service='Database', level='debug', message="Error in filtering to local peer only: " + str(E), redisClient=self.redisMessaging)
                        continue
                else:
                    Served_Subs[result['imsi']] = result
                    self.logTool.log(service='Database', level='debug', message="Processed result", redisClient=self.redisMessaging)

        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        self.logTool.log(service='Database', level='debug', message="Final Served_Subs: " + str(Served_Subs), redisClient=self.redisMessaging)
        self.safe_close(session)
        return Served_Subs


    def Get_Served_PCRF_Subscribers(self, get_local_users_only=False):
        self.logTool.log(service='Database', level='debug', message="Getting all subscribers served by this PCRF", redisClient=self.redisMessaging)
        Session = sessionmaker(bind=self.engine)
        session = Session()
        Served_Subs = {}
        try:
            results = session.query(SERVING_APN).all()
            for result in results:
                result = result.__dict__
                self.logTool.log(service='Database', level='debug', message="Result: " + str(result) + " type: " + str(type(result)), redisClient=self.redisMessaging)
                result = self.Sanitize_Datetime(result)
                result.pop('_sa_instance_state')

                if get_local_users_only == True:
                    self.logTool.log(service='Database', level='debug', message="Filtering to locally served IMS Subs only", redisClient=self.redisMessaging)
                    try:
                        serving_pcrf = result['serving_pgw_peer'].split(';')[1]
                        self.logTool.log(service='Database', level='debug', message="Serving PCRF: " + str(serving_pcrf) + " and this is: " + str(self.config['hss']['OriginHost']), redisClient=self.redisMessaging)
                        if serving_pcrf == self.config['hss']['OriginHost']:
                            self.logTool.log(service='Database', level='debug', message="Serving PCRF matches local PCRF", redisClient=self.redisMessaging)
                            self.logTool.log(service='Database', level='debug', message="Processed result", redisClient=self.redisMessaging)
                            
                        else:
                            self.logTool.log(service='Database', level='debug', message="Sub is served by remote PCRF: " + str(serving_pcrf), redisClient=self.redisMessaging)
                            continue
                    except Exception as E:
                        self.logTool.log(service='Database', level='debug', message="Error in filtering Get_Served_PCRF_Subscribers to local peer only: " + str(E), redisClient=self.redisMessaging)
                        continue

                # Get APN Info
                apn_info = self.GetObj(APN, result['apn'])
                #self.logTool.log(service='Database', level='debug', message="Got APN Info: " + str(apn_info), redisClient=self.redisMessaging)
                result['apn_info'] = apn_info

                # Get Subscriber Info
                subscriber_info = self.GetObj(SUBSCRIBER, result['subscriber_id'])
                result['subscriber_info'] = subscriber_info

                #self.logTool.log(service='Database', level='debug', message="Got Subscriber Info: " + str(subscriber_info), redisClient=self.redisMessaging)

                Served_Subs[subscriber_info['imsi']] = result
                self.logTool.log(service='Database', level='debug', message="Processed result", redisClient=self.redisMessaging)
        except Exception as E:
            raise ValueError(E)
        #self.logTool.log(service='Database', level='debug', message="Final SERVING_APN: " + str(Served_Subs), redisClient=self.redisMessaging)
        self.safe_close(session)
        return Served_Subs

    def Get_Vectors_AuC(self, auc_id, action, **kwargs):
        self.logTool.log(service='Database', level='debug', message="Getting Vectors for auc_id " + str(auc_id) + " with action " + str(action), redisClient=self.redisMessaging)
        key_data = self.GetObj(AUC, auc_id)
        vector_dict = {}
        
        if action == "air":
            rand, xres, autn, kasme = S6a_crypt.generate_eutran_vector(key_data['ki'], key_data['opc'], key_data['amf'], key_data['sqn'], kwargs['plmn']) 
            vector_dict['rand'] = rand
            vector_dict['xres'] = xres
            vector_dict['autn'] = autn
            vector_dict['kasme'] = kasme

            #Incriment SQN
            self.Update_AuC(auc_id, sqn=key_data['sqn']+100)

            return vector_dict

        elif action == "sqn_resync":
            self.logTool.log(service='Database', level='debug', message="Resync SQN", redisClient=self.redisMessaging)
            rand = kwargs['rand']       
            sqn, mac_s = S6a_crypt.generate_resync_s6a(key_data['ki'], key_data['opc'], key_data['amf'], kwargs['auts'], rand)
            self.logTool.log(service='Database', level='debug', message="SQN from resync: " + str(sqn) + " SQN in DB is "  + str(key_data['sqn']) + "(Difference of " + str(int(sqn) - int(key_data['sqn'])) + ")", redisClient=self.redisMessaging)
            self.Update_AuC(auc_id, sqn=sqn+100)
            return
        
        elif action == "sip_auth":
            rand, autn, xres, ck, ik = S6a_crypt.generate_maa_vector(key_data['ki'], key_data['opc'], key_data['amf'], key_data['sqn'], kwargs['plmn'])
            self.logTool.log(service='Database', level='debug', message="RAND is: " + str(rand), redisClient=self.redisMessaging)
            self.logTool.log(service='Database', level='debug', message="AUTN is: " + str(autn), redisClient=self.redisMessaging)
            vector_dict['SIP_Authenticate'] = rand + autn
            vector_dict['xres'] = xres
            vector_dict['ck'] = ck
            vector_dict['ik'] = ik
            self.Update_AuC(auc_id, sqn=key_data['sqn']+100)
            return vector_dict

        elif action == "2g3g":
            rand, autn, xres, ck, ik = S6a_crypt.generate_maa_vector(key_data['ki'], key_data['opc'], key_data['amf'], key_data['sqn'], kwargs['plmn'])
            vector_list = []
            self.logTool.log(service='Database', level='debug', message="Generating " + str(kwargs['requested_vectors']) + " vectors for GSM use", redisClient=self.redisMessaging)
            while kwargs['requested_vectors'] != 0:
                self.logTool.log(service='Database', level='debug', message="RAND is: " + str(rand), redisClient=self.redisMessaging)
                self.logTool.log(service='Database', level='debug', message="AUTN is: " + str(autn), redisClient=self.redisMessaging)
                
                vector_dict['rand'] = binascii.hexlify(rand).decode("utf-8")
                vector_dict['autn'] = binascii.hexlify(autn).decode("utf-8")
                vector_dict['xres'] = binascii.hexlify(xres).decode("utf-8")
                vector_dict['ck'] = binascii.hexlify(ck).decode("utf-8")
                vector_dict['ik'] = binascii.hexlify(ik).decode("utf-8")
                
                kwargs['requested_vectors'] = kwargs['requested_vectors'] - 1
                vector_list.append(vector_dict)
            self.Update_AuC(auc_id, sqn=key_data['sqn']+100)
            return vector_list

        elif action == "eap_aka":
            rand, xres, autn, mac_a, ak = S6a_crypt.generate_eap_aka_vector(key_data['ki'], key_data['opc'], key_data['amf'], key_data['sqn'], kwargs['plmn'])
            self.logTool.log(service='Database', level='debug', message="RAND is: " + str(rand), redisClient=self.redisMessaging)
            self.logTool.log(service='Database', level='debug', message="AUTN is: " + str(autn), redisClient=self.redisMessaging)
            vector_dict['rand'] = binascii.hexlify(rand).decode("utf-8")
            vector_dict['autn'] = binascii.hexlify(autn).decode("utf-8")
            vector_dict['xres'] = binascii.hexlify(xres).decode("utf-8")
            vector_dict['mac'] = binascii.hexlify(mac_a).decode("utf-8")
            vector_dict['ak'] = binascii.hexlify(ak).decode("utf-8")
            self.Update_AuC(auc_id, sqn=key_data['sqn']+100)
            return vector_dict

        elif action == "Digest-MD5":
            self.logTool.log(service='Database', level='debug', message="Generating Digest-MD5 Auth vectors", redisClient=self.redisMessaging)
            self.logTool.log(service='Database', level='debug', message="key_data: " + str(key_data), redisClient=self.redisMessaging)
            nonce = uuid.uuid4().hex
            #nonce = "beef4d878f2642ed98afe491b943ca60"
            vector_dict['nonce'] = nonce
            vector_dict['SIP_Authenticate'] = key_data['ki']
            return vector_dict
        else:
            self.logTool.log(service='Database', level='error', message="Invalid action: " + str(action), redisClient=self.redisMessaging)

    def Get_APN(self, apn_id):
        self.logTool.log(service='Database', level='debug', message="Getting APN " + str(apn_id), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()

        try:
            result = session.query(APN).filter_by(apn_id=apn_id).one()
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        result = result.__dict__
        result.pop('_sa_instance_state')
        self.safe_close(session)
        return result    

    def Get_APN_by_Name(self, apn):
        self.logTool.log(service='Database', level='debug', message="Getting APN named " + str(apn), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()    
        try:
            result = session.query(APN).filter_by(apn=str(apn)).one()
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        result = result.__dict__
        result.pop('_sa_instance_state')
        self.safe_close(session)
        return result 

    def Update_AuC(self, auc_id, sqn=1, propagate=True):
        self.logTool.log(service='Database', level='debug', message=f"Updating AuC record for ID: {auc_id}", redisClient=self.redisMessaging)
        self.logTool.log(service='Database', level='debug', message=self.UpdateObj(AUC, {'sqn': sqn}, auc_id, True), redisClient=self.redisMessaging)

        if propagate:
            if self.config['geored'].get('enabled', False) == True:
                aucBody = {
                    "auc_id": auc_id,
                    "sqn": sqn,
                }
                self.handleGeored(aucBody)
        self.logTool.log(service='Database', level='debug', message=f"Sent Geored update for AuC: {auc_id} with SQN {sqn}", redisClient=self.redisMessaging)

        return

    def Update_Serving_MME(self, imsi, serving_mme, serving_mme_realm=None, serving_mme_peer=None, serving_mme_timestamp=None, propagate=True):
        self.logTool.log(service='Database', level='debug', message="Updating Serving MME for sub " + str(imsi) + " to MME " + str(serving_mme), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()
        try:
            result = session.query(SUBSCRIBER).filter_by(imsi=imsi).one()
            if self.config['hss']['CancelLocationRequest_Enabled'] == True:
                self.logTool.log(service='Database', level='debug', message="Evaluating if we should trigger sending a CLR.", redisClient=self.redisMessaging)
                serving_hss = str(result.serving_mme_peer).split(';',1)[1]
                serving_mme_peer = str(result.serving_mme_peer).split(';',1)[0]
                self.logTool.log(service='Database', level='debug', message="Subscriber is currently served by serving_mme: " + str(result.serving_mme) + " at realm " + str(result.serving_mme_realm) + " through Diameter peer " + str(result.serving_mme_peer), redisClient=self.redisMessaging)
                self.logTool.log(service='Database', level='debug', message="Subscriber is now       served by serving_mme: " + str(serving_mme) + " at realm " + str(serving_mme_realm) + " through Diameter peer " + str(serving_mme_peer), redisClient=self.redisMessaging)
                #Evaluate if we need to send a CLR to the old MME
                if result.serving_mme != None:
                    if str(result.serving_mme) == str(serving_mme):
                        self.logTool.log(service='Database', level='debug', message="This MME is unchanged (" + str(serving_mme) + ") - so no need to send a CLR", redisClient=self.redisMessaging)
                    elif (str(result.serving_mme) != str(serving_mme)):
                        self.logTool.log(service='Database', level='debug', message="There is a difference in serving MME, old MME is '" + str(result.serving_mme) + "' new MME is '" + str(serving_mme) + "' - We need to trigger sending a CLR", redisClient=self.redisMessaging)
                        if serving_hss != self.config['hss']['OriginHost']:
                            self.logTool.log(service='Database', level='debug', message="This subscriber is not served by this HSS it is served by HSS at " + serving_hss + " - We need to trigger sending a CLR on " + str(serving_hss), redisClient=self.redisMessaging)
                            URL = 'http://' + serving_hss + '.' + self.config['hss']['OriginRealm'] + ':8080/push/clr/' + str(imsi)
                        else:
                            self.logTool.log(service='Database', level='debug', message="This subscriber is served by this HSS we need to send a CLR to old MME from this HSS", redisClient=self.redisMessaging)
                        
                        URL = 'http://' + serving_hss + '.' + self.config['hss']['OriginRealm'] + ':8080/push/clr/' + str(imsi)
                        self.logTool.log(service='Database', level='debug', message="Sending CLR to API at " + str(URL), redisClient=self.redisMessaging)

                        clrBody = {
                            "imsi": str(imsi), 
                            "DestinationRealm": result.serving_mme_realm,
                            "DestinationHost": result.serving_mme,
                            "cancellationType": 2,
                            "diameterPeer": serving_mme_peer,
                            }
                        
                        self.logTool.log(service='Database', level='debug', message="Pushing CLR to API on " + str(URL) + " with JSON body: " + str(clrBody), redisClient=self.redisMessaging)
                        transaction_id = str(uuid.uuid4())
                        self.handleGeored(clrBody, asymmetric=True, asymmetricUrls=[URL])
                else:
                    #No currently serving MME - No action to take
                    self.logTool.log(service='Database', level='debug', message="No currently serving MME - No need to send CLR", redisClient=self.redisMessaging)

            if type(serving_mme) == str:
                self.logTool.log(service='Database', level='debug', message="Updating serving MME & Timestamp", redisClient=self.redisMessaging)
                result.serving_mme = serving_mme
                try:
                    if serving_mme_timestamp != None and serving_mme_timestamp != 'None':
                        result.serving_mme_timestamp = datetime.strptime(serving_mme_timestamp, '%Y-%m-%dT%H:%M:%SZ')
                        result.serving_mme_timestamp = result.serving_mme_timestamp.replace(tzinfo=timezone.utc)
                        serving_mme_timestamp_string = result.serving_mme_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                    else:
                        result.serving_mme_timestamp = datetime.datetime.now(tz=timezone.utc)
                        serving_mme_timestamp_string = result.serving_mme_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                except Exception as e:
                    result.serving_mme_timestamp = datetime.datetime.now(tz=timezone.utc)
                    serving_mme_timestamp_string = result.serving_mme_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                result.serving_mme_realm = serving_mme_realm
                result.serving_mme_peer = serving_mme_peer
            else:
                #Clear values
                self.logTool.log(service='Database', level='debug', message="Clearing serving MME", redisClient=self.redisMessaging)
                result.serving_mme = None
                result.serving_mme_timestamp = None
                result.serving_mme_realm = None
                result.serving_mme_peer = None
                serving_mme_timestamp_string = datetime.datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

            session.commit()
            objectData = self.GetObj(SUBSCRIBER, result.subscriber_id)
            self.handleWebhook(objectData, 'PATCH')

            #Sync state change with geored
            if propagate == True:
                if 'HSS' in self.config['geored'].get('sync_actions', []) and self.config['geored'].get('enabled', False) == True:
                    self.logTool.log(service='Database', level='debug', message="Propagate MME changes to Geographic PyHSS instances", redisClient=self.redisMessaging)
                    self.handleGeored({
                        "imsi": str(imsi), 
                        "serving_mme": result.serving_mme, 
                        "serving_mme_realm": result.serving_mme_realm, 
                        "serving_mme_peer": result.serving_mme_peer,
                        "serving_mme_timestamp": serving_mme_timestamp_string
                        })
                else:
                    self.logTool.log(service='Database', level='debug', message="Config does not allow sync of HSS events", redisClient=self.redisMessaging)
        except Exception as E:
            self.logTool.log(service='Database', level='error', message="Error occurred in Update_Serving_MME: " + str(E), redisClient=self.redisMessaging)
        finally:
            self.safe_close(session)


    def Update_Proxy_CSCF(self, imsi, proxy_cscf, pcscf_realm=None, pcscf_peer=None, pcscf_timestamp=None, pcscf_active_session=None, propagate=True):
        self.logTool.log(service='Database', level='debug', message="Update_Proxy_CSCF for sub " + str(imsi) + " to pcscf " + str(proxy_cscf) + " with realm " + str(pcscf_realm) + " and peer " + str(pcscf_peer) + " for session id " + str(pcscf_active_session), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()

        try:
            result = session.query(IMS_SUBSCRIBER).filter_by(imsi=imsi).one()
            try:
                assert(type(proxy_cscf) == str)
                assert(len(proxy_cscf) > 0)
                self.logTool.log(service='Database', level='debug', message="Setting Proxy CSCF", redisClient=self.redisMessaging)
                #Strip duplicate SIP prefix before storing
                proxy_cscf = proxy_cscf.replace("sip:sip:", "sip:")
                result.pcscf = proxy_cscf
                result.pcscf_active_session = pcscf_active_session
                try:
                    if pcscf_timestamp != None and pcscf_timestamp != 'None':
                        result.pcscf_timestamp = datetime.strptime(pcscf_timestamp, '%Y-%m-%dT%H:%M:%SZ')
                        result.pcscf_timestamp = result.pcscf_timestamp.replace(tzinfo=timezone.utc)
                        pcscf_timestamp_string = result.pcscf_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                    else:
                        result.pcscf_timestamp = datetime.datetime.now(tz=timezone.utc)
                        pcscf_timestamp_string = result.pcscf_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                except Exception as e:
                    result.pcscf_timestamp = datetime.datetime.now(tz=timezone.utc)
                    pcscf_timestamp_string = result.pcscf_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                result.pcscf_realm = pcscf_realm
                result.pcscf_peer = str(pcscf_peer)
            except:
                #Clear values
                self.logTool.log(service='Database', level='debug', message="Clearing Proxy CSCF", redisClient=self.redisMessaging)
                result.pcscf = None
                result.pcscf_timestamp = None
                result.pcscf_realm = None
                result.pcscf_peer = None
                result.pcscf_active_session = None
                pcscf_timestamp_string = datetime.datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

            session.commit()
            objectData = self.GetObj(IMS_SUBSCRIBER, result.ims_subscriber_id)
            self.handleWebhook(objectData, 'PATCH')

            #Sync state change with geored
            if propagate == True:
                if 'IMS' in self.config['geored']['sync_actions'] and self.config['geored']['enabled'] == True:
                    self.logTool.log(service='Database', level='debug', message="Propagate IMS changes to Geographic PyHSS instances", redisClient=self.redisMessaging)
                    self.handleGeored({"imsi": str(imsi), "pcscf": result.pcscf, "pcscf_realm": result.pcscf_realm, "pcscf_timestamp": pcscf_timestamp_string, "pcscf_peer": result.pcscf_peer, "pcscf_active_session": pcscf_active_session})
                else:
                    self.logTool.log(service='Database', level='debug', message="Config does not allow sync of IMS events", redisClient=self.redisMessaging)
        except Exception as E:
            self.logTool.log(service='Database', level='error', message="An error occurred, rolling back session: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            raise
        finally:
            self.safe_close(session)

    def Update_Serving_CSCF(self, imsi, serving_cscf, scscf_realm=None, scscf_peer=None, scscf_timestamp=None, propagate=True):
        self.logTool.log(service='Database', level='debug', message="Update_Serving_CSCF for sub " + str(imsi) + " to SCSCF " + str(serving_cscf) + " with realm " + str(scscf_realm) + " and peer " + str(scscf_peer), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()

        try:
            result = session.query(IMS_SUBSCRIBER).filter_by(imsi=imsi).one()
            try:
                assert(type(serving_cscf) == str)
                assert(len(serving_cscf) > 0)
                self.logTool.log(service='Database', level='debug', message="Setting serving CSCF", redisClient=self.redisMessaging)
                #Strip duplicate SIP prefix before storing
                serving_cscf = serving_cscf.replace("sip:sip:", "sip:")
                result.scscf = serving_cscf
                try:
                    if scscf_timestamp != None and scscf_timestamp != 'None':
                        result.scscf_timestamp = datetime.strptime(scscf_timestamp, '%Y-%m-%dT%H:%M:%SZ')
                        result.scscf_timestamp = result.scscf_timestamp.replace(tzinfo=timezone.utc)
                        scscf_timestamp_string = result.scscf_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                    else:
                        result.scscf_timestamp = datetime.datetime.now(tz=timezone.utc)
                        scscf_timestamp_string = result.scscf_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                except Exception as e:
                    result.scscf_timestamp = datetime.datetime.now(tz=timezone.utc)
                    scscf_timestamp_string = result.scscf_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                result.scscf_realm = scscf_realm
                result.scscf_peer = str(scscf_peer)
            except:
                #Clear values
                self.logTool.log(service='Database', level='debug', message="Clearing serving CSCF", redisClient=self.redisMessaging)
                result.scscf = None
                result.scscf_timestamp = None
                result.scscf_realm = None
                result.scscf_peer = None
                scscf_timestamp_string = datetime.datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            
            session.commit()
            objectData = self.GetObj(IMS_SUBSCRIBER, result.ims_subscriber_id)
            self.handleWebhook(objectData, 'PATCH')

            #Sync state change with geored
            if propagate == True:
                if 'IMS' in self.config['geored']['sync_actions'] and self.config['geored']['enabled'] == True:
                    self.logTool.log(service='Database', level='debug', message="Propagate IMS changes to Geographic PyHSS instances", redisClient=self.redisMessaging)
                    self.handleGeored({"imsi": str(imsi), "scscf": result.scscf, "scscf_realm": result.scscf_realm, "scscf_timestamp": scscf_timestamp_string, "scscf_peer": result.scscf_peer})
                else:
                    self.logTool.log(service='Database', level='debug', message="Config does not allow sync of IMS events", redisClient=self.redisMessaging)
        except Exception as E:
            self.logTool.log(service='Database', level='error', message="An error occurred, rolling back session: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            raise
        finally:
            self.safe_close(session)

    def Update_Serving_APN(self, imsi, apn, pcrf_session_id, serving_pgw, subscriber_routing, serving_pgw_realm=None, serving_pgw_peer=None, serving_pgw_timestamp=None, propagate=True):
        self.logTool.log(service='Database', level='debug', message="Called Update_Serving_APN() for imsi " + str(imsi) + " with APN " + str(apn), redisClient=self.redisMessaging)
        self.logTool.log(service='Database', level='debug', message="PCRF Session ID " + str(pcrf_session_id) + " and serving PGW " + str(serving_pgw) + " and subscriber routing " + str(subscriber_routing), redisClient=self.redisMessaging)
        self.logTool.log(service='Database', level='debug', message="Serving PGW Realm is: " + str(serving_pgw_realm) + " and peer is: " + str(serving_pgw_peer), redisClient=self.redisMessaging)
        self.logTool.log(service='Database', level='debug', message="subscriber_routing: " + str(subscriber_routing), redisClient=self.redisMessaging)

        #Get Subscriber ID from IMSI
        subscriber_details = self.Get_Subscriber(imsi=str(imsi))
        subscriber_id = subscriber_details['subscriber_id']

        #Split the APN list into a list
        apn_list = subscriber_details['apn_list'].split(',')
        self.logTool.log(service='Database', level='debug', message="Current APN List: " + str(apn_list), redisClient=self.redisMessaging)
        #Remove the default APN from the list
        try:
            apn_list.remove(str(subscriber_details['default_apn']))
        except:
            self.logTool.log(service='Database', level='debug', message="Failed to remove default APN (" + str(subscriber_details['default_apn']) + " from APN List", redisClient=self.redisMessaging)
            pass
        #Add default APN in first position
        apn_list.insert(0, str(subscriber_details['default_apn']))

        #Get APN ID from APN
        for apn_id in apn_list:
            #Get each APN in List
            apn_data = self.Get_APN(apn_id)
            self.logTool.log(service='Database', level='debug', message=apn_data, redisClient=self.redisMessaging)
            if str(apn_data['apn']).lower() == str(apn).lower():
                self.logTool.log(service='Database', level='debug', message="Matched named APN " + str(apn_data['apn']) + " with APN ID " + str(apn_id), redisClient=self.redisMessaging)
                break
        self.logTool.log(service='Database', level='debug', message="APN ID is " + str(apn_id), redisClient=self.redisMessaging)

        try:
            if serving_pgw_timestamp != None and serving_pgw_timestamp != 'None':
                serving_pgw_timestamp = datetime.strptime(serving_pgw_timestamp, '%Y-%m-%dT%H:%M:%SZ')
                serving_pgw_timestamp = serving_pgw_timestamp.replace(tzinfo=timezone.utc)
                serving_pgw_timestamp_string = serving_pgw_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
            else:
                serving_pgw_timestamp = datetime.datetime.now(tz=timezone.utc)
                serving_pgw_timestamp_string = serving_pgw_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception as e:
            serving_pgw_timestamp = datetime.datetime.now(tz=timezone.utc)
            serving_pgw_timestamp_string = serving_pgw_timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
        serving_pgw_realm = serving_pgw_realm
        serving_pgw_peer = serving_pgw_peer

        json_data = {
            'apn' : apn_id,
            'subscriber_id' : subscriber_id,
            'pcrf_session_id' : str(pcrf_session_id),
            'serving_pgw' : str(serving_pgw),
            'serving_pgw_realm' : str(serving_pgw_realm),
            'serving_pgw_peer' : str(serving_pgw_peer),
            'serving_pgw_timestamp' : serving_pgw_timestamp,
            'subscriber_routing' : str(subscriber_routing)
        }

        if serving_pgw is None:
            try:
                ServingAPN = self.Get_Serving_APN(subscriber_id=subscriber_id, apn_id=apn_id)
                self.logTool.log(service='Database', level='debug', message="Clearing PCRF session ID on serving_apn_id: " + str(ServingAPN['serving_apn_id']), redisClient=self.redisMessaging)
                objectData = self.GetObj(SERVING_APN, ServingAPN['serving_apn_id'])
                self.handleWebhook(objectData, 'DELETE')
                self.DeleteObj(SERVING_APN, ServingAPN['serving_apn_id'], True)
            except Exception as e:
                self.logTool.log(service='Database', level='debug', message=f"Error when trying to delete serving_apn id: {apn_id}", redisClient=self.redisMessaging)
        else:
            try:
            #Check if already a serving APN on record
                self.logTool.log(service='Database', level='debug', message="Checking to see if subscriber id " + str(subscriber_id) + " already has an active PCRF profile on APN id " + str(apn_id), redisClient=self.redisMessaging)
                ServingAPN = self.Get_Serving_APN(subscriber_id=subscriber_id, apn_id=apn_id)
                self.logTool.log(service='Database', level='debug', message="Existing Serving APN ID on record, updating", redisClient=self.redisMessaging)
                try:
                    assert(type(serving_pgw) == str)
                    assert(len(serving_pgw) > 0)
                    assert("None" not in serving_pgw)
                    
                    self.UpdateObj(SERVING_APN, json_data, ServingAPN['serving_apn_id'], True)
                    objectData = self.GetObj(SERVING_APN, ServingAPN['serving_apn_id'])
                    self.handleWebhook(objectData, 'PATCH')
                except:
                    self.logTool.log(service='Database', level='debug', message="Clearing PCRF session ID on serving_apn_id: " + str(ServingAPN['serving_apn_id']), redisClient=self.redisMessaging)
                    objectData = self.GetObj(SERVING_APN, ServingAPN['serving_apn_id'])
                    self.handleWebhook(objectData, 'DELETE')
                    self.DeleteObj(SERVING_APN, ServingAPN['serving_apn_id'], True)
            except Exception as E:
                self.logTool.log(service='Database', level='debug', message="Failed to update existing APN " + str(E), redisClient=self.redisMessaging)
                #Create if does not exist
                self.CreateObj(SERVING_APN, json_data, True)
                ServingAPN = self.Get_Serving_APN(subscriber_id=subscriber_id, apn_id=apn_id)
                objectData = self.GetObj(SERVING_APN, ServingAPN['serving_apn_id'])
                self.handleWebhook(objectData, 'PUT')

        #Sync state change with geored
        if propagate == True:
            try:
                if 'PCRF' in self.config['geored']['sync_actions'] and self.config['geored']['enabled'] == True:
                    self.logTool.log(service='Database', level='debug', message="Propagate PCRF changes to Geographic PyHSS instances", redisClient=self.redisMessaging)
                    self.handleGeored({"imsi": str(imsi),
                                    'serving_apn' : apn,
                                    'pcrf_session_id': pcrf_session_id,
                                    'serving_pgw': serving_pgw,
                                    'serving_pgw_realm': serving_pgw_realm,
                                    'serving_pgw_peer': serving_pgw_peer,
                                    'serving_pgw_timestamp': serving_pgw_timestamp_string,
                                    'subscriber_routing': subscriber_routing
                                    })
                else:
                    self.logTool.log(service='Database', level='debug', message="Config does not allow sync of PCRF events", redisClient=self.redisMessaging)
            except Exception as E:
                self.logTool.log(service='Database', level='debug', message="Nothing synced to Geographic PyHSS instances for event PCRF", redisClient=self.redisMessaging)

            return

    def Get_Serving_APN(self, subscriber_id, apn_id):
        self.logTool.log(service='Database', level='debug', message="Getting Serving APN " + str(apn_id) + " with subscriber_id " + str(subscriber_id), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()

        try:
            result = session.query(SERVING_APN).filter_by(subscriber_id=subscriber_id, apn=apn_id).first()
        except Exception as E:
            self.logTool.log(service='Database', level='debug', message=E, redisClient=self.redisMessaging)
            self.safe_close(session)
            raise ValueError(E)
        result = result.__dict__
        result.pop('_sa_instance_state')
        
        self.safe_close(session)
        return result   

    def Get_Serving_APNs(self, subscriber_id: int) -> dict:
        """
        Returns all a dictionary containing all APNs that a subscriber is configured for (subscriber/apn_list), 
        with active sessions being a populated dictionary, and inactive sessions being an empty dictionary.
        """
        self.logTool.log(service='Database', level='debug', message=f"Getting Serving APNs for subscriber_id: {subscriber_id}", redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()
        apnDict = {'apns': {}}

        try:
            subscriber = self.Get_Subscriber(subscriber_id=subscriber_id)
        except:
            self.logTool.log(service='Database', level='debug', message=f"Unable to get subscriber with ID: {subscriber_id}: {traceback.format_exc()} ", redisClient=self.redisMessaging)
            return apnDict
        
        apnList = subscriber.get('apn_list', []).split(',')
        for apnId in apnList:
            try:
                apnData = self.Get_APN(apnId)
                apnName = apnData.get('apn', 'Unknown')
                try:
                    servingApn = self.Sanitize_Datetime(self.Get_Serving_APN(subscriber_id=subscriber_id, apn_id=apnId))
                    self.logTool.log(service='Database', level='debug', message=f"Got serving APN: {servingApn}", redisClient=self.redisMessaging)
                    if len(servingApn) > 0:
                        apnDict['apns'][apnName] = servingApn
                    else:
                        apnDict['apns'][apnName] = {}
                except Exception as e:
                    apnDict['apns'][apnName] = {}
                    continue
            except Exception as E:
                self.logTool.log(service='Database', level='debug', message=f"Error getting apn for subscriber id: {subscriber_id}: {traceback.format_exc()} ", redisClient=self.redisMessaging)
        
        self.logTool.log(service='Database', level='debug', message=f"Returning: {apnDict}", redisClient=self.redisMessaging)

        return apnDict

    def Get_Charging_Rule(self, charging_rule_id):
        self.logTool.log(service='Database', level='debug', message="Called Get_Charging_Rule() for  charging_rule_id " + str(charging_rule_id), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()
        #Get base Rule
        ChargingRule = self.GetObj(CHARGING_RULE, charging_rule_id)
        ChargingRule['tft'] = []
        #Get TFTs
        try:
            results = session.query(TFT).filter_by(tft_group_id=ChargingRule['tft_group_id'])
            for result in results:
                result = result.__dict__
                result.pop('_sa_instance_state')
                ChargingRule['tft'].append(result)
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        self.safe_close(session)
        return ChargingRule

    def Get_Charging_Rules(self, imsi, apn):
        self.logTool.log(service='Database', level='debug', message="Called Get_Charging_Rules() for IMSI " + str(imsi) + " and APN " + str(apn), redisClient=self.redisMessaging)
        #Get Subscriber ID from IMSI
        subscriber_details = self.Get_Subscriber(imsi=str(imsi))

        #Split the APN list into a list
        apn_list = subscriber_details['apn_list'].split(',')
        self.logTool.log(service='Database', level='debug', message="Current APN List: " + str(apn_list), redisClient=self.redisMessaging)
        #Remove the default APN from the list
        try:
            apn_list.remove(str(subscriber_details['default_apn']))
        except:
            self.logTool.log(service='Database', level='debug', message="Failed to remove default APN (" + str(subscriber_details['default_apn']) + " from APN List", redisClient=self.redisMessaging)
            pass
        #Add default APN in first position
        apn_list.insert(0, str(subscriber_details['default_apn']))

        #Get APN ID from APN
        for apn_id in apn_list:
            self.logTool.log(service='Database', level='debug', message="Getting APN ID " + str(apn_id) + " to see if it matches APN " + str(apn), redisClient=self.redisMessaging)
            #Get each APN in List
            apn_data = self.Get_APN(apn_id)
            self.logTool.log(service='Database', level='debug', message=apn_data, redisClient=self.redisMessaging)
            if str(apn_data['apn']).lower() == str(apn).lower():
                self.logTool.log(service='Database', level='debug', message="Matched named APN " + str(apn_data['apn']) + " with APN ID " + str(apn_id), redisClient=self.redisMessaging)

                self.logTool.log(service='Database', level='debug', message="Getting charging rule list from " + str(apn_data['charging_rule_list']), redisClient=self.redisMessaging)
                ChargingRule = {}
                ChargingRule['charging_rule_list'] = str(apn_data['charging_rule_list']).split(',')
                ChargingRule['apn_data'] = apn_data

                #Get Charging Rules list
                if apn_data['charging_rule_list'] == None:
                    self.logTool.log(service='Database', level='debug', message="No Charging Rule associated with this APN", redisClient=self.redisMessaging)
                    ChargingRule['charging_rules'] = None
                    return ChargingRule

                self.logTool.log(service='Database', level='debug', message="ChargingRule['charging_rule_list'] is: " + str(ChargingRule['charging_rule_list']), redisClient=self.redisMessaging)
                #Empty dict for the Charging Rules to go into
                ChargingRule['charging_rules'] = []
                #Add each of the Charging Rules for the APN
                for individual_charging_rule in ChargingRule['charging_rule_list']:
                    self.logTool.log(service='Database', level='debug', message="Getting Charging rule " + str(individual_charging_rule), redisClient=self.redisMessaging)
                    individual_charging_rule_complete = self.Get_Charging_Rule(individual_charging_rule)
                    self.logTool.log(service='Database', level='debug', message="Got individual_charging_rule_complete: " + str(individual_charging_rule_complete), redisClient=self.redisMessaging)
                    ChargingRule['charging_rules'].append(individual_charging_rule_complete)
                self.logTool.log(service='Database', level='debug', message="Completed Get_Charging_Rules()", redisClient=self.redisMessaging)
                self.logTool.log(service='Database', level='debug', message=ChargingRule, redisClient=self.redisMessaging)
                return ChargingRule

    def Get_UE_by_IP(self, subscriber_routing):   
        self.logTool.log(service='Database', level='debug', message="Called Get_UE_by_IP() for IP " + str(subscriber_routing), redisClient=self.redisMessaging)

        Session = sessionmaker(bind = self.engine)
        session = Session()    
        
        try:
            result = session.query(SERVING_APN).filter_by(subscriber_routing=subscriber_routing).one()
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        result = result.__dict__
        result.pop('_sa_instance_state')
        result = self.Sanitize_Datetime(result)
        return result

    def Get_IMS_Subscriber_By_Session_Id(self, sessionId):   
        self.logTool.log(service='Database', level='debug', message="Called Get_IMS_Subscriber_By_Session_Id() for Session " + str(sessionId), redisClient=self.redisMessaging)

        Session = sessionmaker(bind = self.engine)
        session = Session()    
        
        try:
            result = session.query(IMS_SUBSCRIBER).filter_by(pcscf_active_session=sessionId).one()
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)
        result = result.__dict__
        result.pop('_sa_instance_state')
        result = self.Sanitize_Datetime(result)
        return result

    def Store_IMSI_IMEI_Binding(self, imsi, imei, match_response_code, propagate=True):
        #IMSI           14-15 Digits
        #IMEI           15 Digits
        #IMEI-SV        2 Digits
        self.logTool.log(service='Database', level='debug', message="Called Store_IMSI_IMEI_Binding() with IMSI: " + str(imsi) + " IMEI: " + str(imei) + " match_response_code: " + str(match_response_code), redisClient=self.redisMessaging)
        if self.config['eir']['imsi_imei_logging'] != True:
            self.logTool.log(service='Database', level='debug', message="Skipping storing binding", redisClient=self.redisMessaging)
            return
        #Concat IMEI + IMSI
        imsi_imei = str(imsi) + "," + str(imei)
        Session = sessionmaker(bind = self.engine)
        session = Session()

        #Check if exist already & update
        try:
            session.query(IMSI_IMEI_HISTORY).filter_by(imsi_imei=imsi_imei).one()
            self.logTool.log(service='Database', level='debug', message="Entry already present for IMSI/IMEI Combo", redisClient=self.redisMessaging)   
            self.safe_close(session)     
            return 
        except Exception as E:
            newObj = IMSI_IMEI_HISTORY(imsi_imei=imsi_imei, match_response_code=match_response_code, imsi_imei_timestamp = datetime.datetime.now(tz=timezone.utc))
            session.add(newObj)
            try:
                session.commit()
            except Exception as E:
                self.logTool.log(service='Database', level='error', message="Failed to commit session, error: " + str(E), redisClient=self.redisMessaging)
                self.safe_rollback(session)
                self.safe_close(session)
                raise ValueError(E)
            self.safe_close(session)
            self.logTool.log(service='Database', level='debug', message="Added new IMSI_IMEI_HISTORY binding", redisClient=self.redisMessaging)

            if 'sim_swap_notify_webhook' in self.config['eir']:
                self.logTool.log(service='Database', level='debug', message="Sending SIM Swap notification to Webhook", redisClient=self.redisMessaging)
                try:
                    dictToSend = {'imei':imei, 'imsi': imsi, 'match_response_code': match_response_code}
                    self.handleWebhook(dictToSend)
                except Exception as E:
                    self.logTool.log(service='Database', level='debug', message="Failed to post to Webhook", redisClient=self.redisMessaging)
                    self.logTool.log(service='Database', level='debug', message=str(E), redisClient=self.redisMessaging)

            #Lookup Device Info
            if 'tac_database_csv' in self.config['eir']:
                try:
                    device_info = self.get_device_info_from_TAC(imei=str(imei))
                    self.logTool.log(service='Database', level='debug', message="Got Device Info: " + str(device_info), redisClient=self.redisMessaging)
                    self.redisMessaging.sendMetric(serviceName='database', metricName='prom_eir_devices',
                                                    metricType='counter', metricAction='inc', 
                                                    metricValue=1, metricHelp='Profile of attached devices',
                                                    metricLabels={'imei_prefix': device_info['tacPrefix'],
                                                                  'device_type': device_info['name'],
                                                                  'device_name': device_info['model']},
                                                    metricExpiry=60)
                except Exception as E:
                    self.logTool.log(service='Database', level='debug', message="Failed to get device info from TAC", redisClient=self.redisMessaging)
                    self.redisMessaging.sendMetric(serviceName='database', metricName='prom_eir_devices',
                                metricType='counter', metricAction='inc', 
                                metricValue=1, metricHelp='Profile of attached devices',
                                metricLabels={'imei_prefix': str(imei)[0:8],
                                                'device_type': 'Unknown',
                                                'device_name': 'Unknown'},
                                metricExpiry=60)
            else:
                self.logTool.log(service='Database', level='debug', message="No TAC database configured, skipping device info lookup", redisClient=self.redisMessaging)

            #Sync state change with geored
            if propagate == True:
                try:
                    if 'EIR' in self.config['geored']['sync_actions'] and self.config['geored']['enabled'] == True:
                        self.logTool.log(service='Database', level='debug', message="Propagate EIR changes to Geographic PyHSS instances", redisClient=self.redisMessaging)
                        self.handleGeored(
                            {"imsi": str(imsi), 
                            "imei": str(imei), 
                            "match_response_code": str(match_response_code)}
                            )
                    else:
                        self.logTool.log(service='Database', level='debug', message="Config does not allow sync of EIR events", redisClient=self.redisMessaging)
                except Exception as E:
                    self.logTool.log(service='Database', level='debug', message="Nothing synced to Geographic PyHSS instances for EIR event", redisClient=self.redisMessaging)
                    self.logTool.log(service='Database', level='debug', message=E, redisClient=self.redisMessaging)

            return

    def Get_IMEI_IMSI_History(self, attribute):
        self.logTool.log(service='Database', level='debug', message="Called Get_IMEI_IMSI_History() for entry matching " + str(self.Get_IMEI_IMSI_History), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()
        result_array = []
        try:
            results = session.query(IMSI_IMEI_HISTORY).filter(IMSI_IMEI_HISTORY.imsi_imei.ilike("%" + str(attribute) + "%")).all()
            for result in results:
                result = result.__dict__
                result.pop('_sa_instance_state')
                result = self.Sanitize_Datetime(result)
                try:
                    result['imsi'] = result['imsi_imei'].split(",")[0]
                except:
                    continue
                try:
                    result['imei'] = result['imsi_imei'].split(",")[1]
                except:
                    continue                
                result_array.append(result)
            self.safe_close(session)
            return result_array
        except Exception as E:
            self.safe_close(session)
            raise ValueError(E)

    def Check_EIR(self, imsi, imei):
        eir_response_code_table = {0 : 'Whitelist', 1: 'Blacklist', 2: 'Greylist'}
        self.logTool.log(service='Database', level='debug', message="Called Check_EIR() for  imsi " + str(imsi) + " and imei: " + str(imei), redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()
        #Check for Exact Matches
        self.logTool.log(service='Database', level='debug', message="Looking for exact matches", redisClient=self.redisMessaging)
        #Check for exact Matches
        try:
            results = session.query(EIR).filter_by(imei=str(imei), regex_mode=0)
            for result in results:
                result = result.__dict__
                match_response_code = result['match_response_code']
                if result['imsi'] == '':
                    self.logTool.log(service='Database', level='debug', message="No IMSI specified in DB, so matching only on IMEI", redisClient=self.redisMessaging)
                    self.Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=match_response_code)
                    return match_response_code
                elif result['imsi'] == str(imsi):
                    self.logTool.log(service='Database', level='debug', message="Matched on IMEI and IMSI", redisClient=self.redisMessaging)
                    self.Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=match_response_code)
                    return match_response_code
        except Exception as E:
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)
        
        self.logTool.log(service='Database', level='debug', message="Did not match any Exact Matches - Checking Regex", redisClient=self.redisMessaging)   
        try:
            results = session.query(EIR).filter_by(regex_mode=1)    #Get all Regex records from DB
            for result in results:
                result = result.__dict__
                match_response_code = result['match_response_code']
                if re.match(result['imei'], imei):
                    self.logTool.log(service='Database', level='debug', message="IMEI matched " + str(result['imei']), redisClient=self.redisMessaging)
                    #Check if IMSI also specified
                    if len(result['imsi']) != 0:
                        self.logTool.log(service='Database', level='debug', message="With IMEI matched, now checking if IMSI matches regex", redisClient=self.redisMessaging)
                        if re.match(result['imsi'], imsi):
                            self.logTool.log(service='Database', level='debug', message="IMSI also matched, so match OK!", redisClient=self.redisMessaging)
                            self.Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=match_response_code)
                            return match_response_code
                    else:
                        self.logTool.log(service='Database', level='debug', message="No IMSI specified, so match OK!", redisClient=self.redisMessaging)
                        self.Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=match_response_code)
                        return match_response_code
        except Exception as E:
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)

        try:
            session.commit()
        except Exception as E:
            self.logTool.log(service='Database', level='error', message="Failed to commit session, error: " + str(E), redisClient=self.redisMessaging)
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)
        self.logTool.log(service='Database', level='debug', message="No matches at all - Returning default response", redisClient=self.redisMessaging)
        self.Store_IMSI_IMEI_Binding(imsi=imsi, imei=imei, match_response_code=self.config['eir']['no_match_response'])
        self.safe_close(session)
        return self.config['eir']['no_match_response']

    def Get_EIR_Rules(self):
        self.logTool.log(service='Database', level='debug', message="Getting all EIR Rules", redisClient=self.redisMessaging)
        Session = sessionmaker(bind = self.engine)
        session = Session()
        EIR_Rules = []
        try:
            results = session.query(EIR)
            for result in results:
                result = result.__dict__
                result.pop('_sa_instance_state')
                EIR_Rules.append(result)
        except Exception as E:
            self.safe_rollback(session)
            self.safe_close(session)
            raise ValueError(E)
        self.logTool.log(service='Database', level='debug', message="Final EIR_Rules: " + str(EIR_Rules), redisClient=self.redisMessaging)
        self.safe_close(session)
        return EIR_Rules 


    def dict_bytes_to_dict_string(self, dict_bytes):
        dict_string = {}
        for key, value in dict_bytes.items():
            dict_string[key.decode()] = value.decode()
        return 
        
    def find_imei_in_tac_list(self, imei, tacList):
        """
        Iterate over every tac in the tacList and try to match the first 8 digits of the IMEI.
        If that fails, try to match the first 6 digits of the IMEI.
        """
        for tac in tacList['tacList']:
            for key, value in tac.items():
                if str(key) == str(imei[0:8]):
                    return {'tacPrefix': key, 'name': tac[key]['name'], 'model': tac[key]['model']}
            for key, value in tac.items():
                if str(key) == str(imei[0:6]):
                    return {'tacPrefix': key, 'name': tac[key]['name'], 'model': tac[key]['model']}
        return {}

    def get_device_info_from_TAC(self, imei) -> dict:
        self.logTool.log(service='Database', level='debug', message="Getting Device Info from IMEI: " + str(imei), redisClient=self.redisMessaging)
        try:
            self.logTool.log(service='Database', level='debug', message="Taclist: self.tacList ", redisClient=self.redisMessaging)
            imei_result = self.find_imei_in_tac_list(imei, self.tacData)
            assert(len(imei_result) != 0)
            self.logTool.log(service='Database', level='debug', message="Found match for IMEI " + str(imei) + " with result " + str(imei_result), redisClient=self.redisMessaging)
            return imei_result
        except:
            self.logTool.log(service='Database', level='debug', message="Failed to match on 8 digit IMEI", redisClient=self.redisMessaging)

        raise ValueError("No matching TAC in IMEI Database")


if __name__ == "__main__":
    import binascii,os,pprint
    DeleteAfter = True
    database = Database()

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
    ChargingRule_newObj_A = database.CreateObj(CHARGING_RULE, charging_rule)
    print("ChargingRule_newObj A: " + str(ChargingRule_newObj_A))
    charging_rule['gbr_ul'], charging_rule['gbr_dl'], charging_rule['mbr_ul'], charging_rule['mbr_dl'] = 256000, 256000, 256000, 256000
    print("Creating Charging Rule B")
    charging_rule['rule_name'], charging_rule['precedence'], charging_rule['tft_group_id'] = 'charging_rule_B', 80, 2
    ChargingRule_newObj_B = database.CreateObj(CHARGING_RULE, charging_rule)
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
    database.CreateObj(TFT, tft_template1)
    database.CreateObj(TFT, tft_template2)

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
    database.CreateObj(TFT, tft_template3)
    database.CreateObj(TFT, tft_template4)


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
    newObj = database.CreateObj(APN, apn2)
    print(newObj)

    print("Getting APN " + str(apn2['apn']))
    print(database.GetObj(APN, newObj['apn_id']))
    apn_id = newObj['apn_id']
    UpdatedObj = newObj
    UpdatedObj['apn'] = 'UpdatedInUnitTest'
    
    print("Updating APN " + str(apn2['apn']))
    newObj = database.UpdateObj(APN, UpdatedObj, newObj['apn_id'])
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
    newObj = database.CreateObj(AUC, auc_json)
    print(newObj)

    #Get AuC
    print("Getting AuC entry")
    newObj = database.GetObj(AUC, newObj['auc_id'])
    auc_id = newObj['auc_id']
    print(newObj)

    #Update AuC
    print("Updating AuC entry")
    newObj['sqn'] = newObj['sqn'] + 10
    newObj = database.UpdateObj(AUC, newObj, auc_id)

    #Generate Vectors
    print("Generating Vectors")
    database.Get_Vectors_AuC(auc_id, "air", plmn='12ff')
    print(database.Get_Vectors_AuC(auc_id, "sip_auth", plmn='12ff'))


    #Update AuC
    database.Update_AuC(auc_id, sqn=100)

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
        existing_sub_data = database.Get_Subscriber(imsi=subscriber_json['imsi'])
        database.DeleteObj(SUBSCRIBER, existing_sub_data['subscriber_id'])
    except:
        print("Did not find old sub to delete")

    print("Creating new Subscriber")
    print(subscriber_json)
    newObj = database.CreateObj(SUBSCRIBER, subscriber_json)
    print(newObj)
    subscriber_id = newObj['subscriber_id']

    #Get SUBSCRIBER
    print("Getting Subscriber")
    newObj = database.GetObj(SUBSCRIBER, subscriber_id)
    print(newObj)

    #Update SUBSCRIBER
    print("Updating Subscriber")
    newObj['ue_ambr_ul'] = 999995
    newObj = database.UpdateObj(SUBSCRIBER, newObj, subscriber_id)

    #Set MME Location for Subscriber
    print("Updating Serving MME for Subscriber")
    database.Update_Serving_MME(imsi=newObj['imsi'], serving_mme="Test123", serving_mme_peer="Test123", serving_mme_realm="TestRealm")

    #Update Serving APN for Subscriber
    print("Updating Serving APN for Subscriber")
    database.Update_Serving_APN(imsi=newObj['imsi'], apn=apn2['apn'], pcrf_session_id='kjsdlkjfd', serving_pgw='pgw.test.com', subscriber_routing='1.2.3.4')

    print("Getting Charging Rule for Subscriber / APN Combo")
    ChargingRule = database.Get_Charging_Rules(imsi=newObj['imsi'], apn=apn2['apn'])
    pprint.pprint(ChargingRule)

    #New IMS Subscriber
    ims_subscriber_json = {
        "msisdn": newObj['msisdn'], 
        "msisdn_list": newObj['msisdn'],
        "imsi": subscriber_json['imsi'],
        "ifc_path" : "default_ifc.xml"
        }
    print(ims_subscriber_json)
    newObj = database.CreateObj(IMS_SUBSCRIBER, ims_subscriber_json)
    print(newObj)
    ims_subscriber_id = newObj['ims_subscriber_id']


    #Test Get Subscriber
    print("Test Getting Subscriber")
    GetSubscriber_Result = database.Get_Subscriber(imsi=subscriber_json['imsi'])
    print(GetSubscriber_Result)

    #Test IMS Get Subscriber
    print("Getting IMS Subscribers")
    print(database.Get_IMS_Subscriber(imsi='001001000000006'))
    print(database.Get_IMS_Subscriber(msisdn='12345678'))

    #Set SCSCF for Subscriber
    database.Update_Serving_CSCF(newObj['imsi'], "NickTestCSCF")
    #Get Served Subscriber List
    print(database.Get_Served_IMS_Subscribers())

    #Clear Serving PGW for PCRF Subscriber
    print("Clear Serving PGW for PCRF Subscriber")
    database.Update_Serving_APN(imsi=newObj['imsi'], apn=apn2['apn'], pcrf_session_id='sessionid123', serving_pgw=None, subscriber_routing=None)

    #Clear MME Location for Subscriber    
    print("Clear MME Location for Subscriber")
    database.Update_Serving_MME(newObj['imsi'], None)

    #Generate Vectors for IMS Subscriber
    print("Generating Vectors for IMS Subscriber")
    print(database.Get_Vectors_AuC(auc_id, "sip_auth", plmn='12ff'))

    #print("Generating Resync for IMS Subscriber")
    #print(Get_Vectors_AuC(auc_id, "sqn_resync", auts='7964347dfdfe432289522183fcfb', rand='1bc9f096002d3716c65e4e1f4c1c0d17'))
    
    #Test getting APNs
    GetAPN_Result = database.Get_APN(GetSubscriber_Result['default_apn'])
    print(GetAPN_Result)

    #handleGeored({"imsi": "001001000000006", "serving_mme": "abc123"})
    

    if DeleteAfter == True:
        #Delete IMS Subscriber
        print(database.DeleteObj(IMS_SUBSCRIBER, ims_subscriber_id))
        #Delete Subscriber
        print(database.DeleteObj(SUBSCRIBER, subscriber_id))
        #Delete AuC
        print(database.DeleteObj(AUC, auc_id))
        #Delete APN
        print(database.DeleteObj(APN, apn_id))

    #Whitelist IMEI / IMSI Binding
    eir_template = {'imei': '1234', 'imsi': '567', 'regex_mode': 0, 'match_response_code': 0}
    database.CreateObj(EIR, eir_template)

    #Blacklist Example
    eir_template = {'imei': '99881232', 'imsi': '', 'regex_mode': 0, 'match_response_code': 1}
    database.CreateObj(EIR, eir_template)

    #IMEI Prefix Regex Example (Blacklist all IMEIs starting with 666)
    eir_template = {'imei': '^666.*', 'imsi': '', 'regex_mode': 1, 'match_response_code': 1}
    database.CreateObj(EIR, eir_template)

    #IMEI Prefix Regex Example (Greylist response for IMEI starting with 777 and IMSI is 1234123412341234)
    eir_template = {'imei': '^777.*', 'imsi': '^1234123412341234$', 'regex_mode': 1, 'match_response_code': 2}
    database.CreateObj(EIR, eir_template)

    print("\n\n\n\n")
    #Check Whitelist (No Match)
    assert database.Check_EIR(imei='1234', imsi='') == 2

    print("\n\n\n\n")
    #Check Whitelist (Matched)
    assert database.Check_EIR(imei='1234', imsi='567') == 0

    print("\n\n\n\n")
    #Check Blacklist (Match)
    assert database.Check_EIR(imei='99881232', imsi='567') == 1

    print("\n\n\n\n")
    #IMEI Prefix Regex Example (Greylist response for IMEI starting with 777 and IMSI is 1234123412341234)
    assert database.Check_EIR(imei='7771234', imsi='1234123412341234') == 2
    
    print(database.Get_IMEI_IMSI_History('1234123412'))


    print("\n\n\n")
    print(database.Generate_JSON_Model_for_Flask(SUBSCRIBER))




