from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Boolean, ForeignKey, select, UniqueConstraint, DateTime
from sqlalchemy_utils import database_exists, create_database
import pprint
pp = pprint.PrettyPrinter(indent=6)
#engine = create_engine('postgresql://dbeaver:password@localhost/college', echo = True)
engine = create_engine('mysql://dbeaver:password@localhost/college', echo = True)

# Create database if it does not exist.
if not database_exists(engine.url):
    create_database(engine.url)
else:
    # Connect the database if exists.
    engine.connect()

meta = MetaData()

apn = Table(
    'apn', meta, 
    Column('apn_id', Integer, primary_key = True), 
    Column('apn', String(50)),
    Column('pgw_address', String(50)),
    Column('sgw_address', String(50)),
    Column('charging_characteristics', String(4)),
    Column('apn_ambr_dl', Integer),
    Column('apn_ambr_ul', Integer),
    Column('qci', Integer),
    Column('arp_priority', Integer),
    Column('arp_preemption_capability', Boolean, default=False),
    Column('arp_preemption_vulnerability', Boolean, default=True)
)

serving_apn = Table(
    'serving_apn', meta, 
    Column('serving_apn_id', Integer, primary_key = True), 
    Column('subscriber_id', Integer, ForeignKey('subscriber.subscriber_id')),
    Column('apn', Integer, ForeignKey('apn.apn_id')),
    Column('serving_mme', String(50)),
    Column('serving_mme_timestamp', DateTime),
)

auc = Table(
    'auc', meta, 
    Column('auc_id', Integer, primary_key = True),
    Column('ki', String(32)),
    Column('opc', String(32)),
    Column('amf', String(4))
)

subscriber = Table(
    'subscriber', meta, 
    Column('subscriber_id', Integer, primary_key = True),
    Column('imsi', String(18), unique=True),
    Column('enabled', Boolean, default=1),
    Column('auc_id', Integer, ForeignKey('auc.auc_id')), 
    Column('default_apn', Integer, ForeignKey('apn.apn_id')),
    Column('apn_list', String(18)),
    Column('sqn', Integer),
    Column('msisdn', String(18), unique=True),
    Column('ue_ambr_dl', Integer, default=999999),
    Column('ue_ambr_ul', Integer, default=999999),
    Column('nam', Integer, default=0),
    Column('subscribed_rau_tau_timer', Integer, default=300),
    Column('serving_mme', String(50)),
    Column('serving_mme_timestamp', DateTime),
)

meta.create_all(engine)
conn = engine.connect()

# #Insert APNs
conn.execute(apn.insert(), [
   {'apn':'internet', 'qci':9, 'apn_ambr_dl':9999, 'apn_ambr_ul': 88888, 'arp_priority': 1, 'arp_preemption_capability' : False, 'arp_preemption_vulnerability': True},
   {'apn':'ims', 'qci':5, 'apn_ambr_dl':11111, 'apn_ambr_ul': 11111, 'arp_priority': 1, 'arp_preemption_capability' : True, 'arp_preemption_vulnerability': False},
   {'apn':'tech', 'qci':6, 'apn_ambr_dl':999999, 'apn_ambr_ul': 999999, 'arp_priority': 1, 'arp_preemption_capability' : True, 'arp_preemption_vulnerability': False},
])

#Retrive APNs
apn_id = 1
#Update APN
stmt=apn.update().where(apn.c.apn_id==apn_id).values(pgw_address='test.com')
conn.execute(stmt)

#Add AuC Entry
result = conn.execute(auc.insert(), [
   {'ki':'kikikikiki', 'opc':'opcopcopc', 'amf' : '8000'},
])
auc_id = result.lastrowid

#Add Subscriber Entry
try:
    conn.execute(subscriber.insert(), [
    {'imsi' : '12345124131235', 'auc_id' : auc_id, 'default_apn': 1, 'apn_list':'1,2,3'},
    ])
except Exception as E:
    print(E)

s = select([subscriber, auc]).where(
    (subscriber.c.subscriber_id == auc.c.auc_id)
    &
    (subscriber.c.imsi == '12345124131235')
)
result = conn.execute(s)
for row in result:
   subscriber_data = dict(row._mapping)


print("subscriber data: ")
#Create PDN list in dict
subscriber_data['pdn'] = []
#Make list of APN IDs as Ints
apn_id_list = list(map(int, subscriber_data['apn_list'].split(',')))
#Get APNs from DB
s = select([apn])
result = conn.execute(s)
for apn_row in result:
    if int(apn_row['apn_id']) in apn_id_list:
        subscriber_data['pdn'].append(dict(apn_row._mapping))
pp.pprint(subscriber_data)