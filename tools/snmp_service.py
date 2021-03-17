#This SNMP service pulls stats written to Redis by PyHSS and presents them as SNMP
import yaml
import sys
with open(sys.path[0] + '/../config.yaml') as stream:
    yaml_config = (yaml.safe_load(stream))

#Pulled from https://stackoverflow.com/questions/58909285/how-to-add-variable-in-the-mib-tree

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.smi import instrum, builder
from pysnmp.proto.api import v2c
import datetime
import redis


import redis
redis_store = redis.Redis(host=str(yaml_config['redis']['host']), port=str(yaml_config['redis']['port']), db=0)
# Create SNMP engine
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode((str(yaml_config['snmp']['listen_address']), int(yaml_config['snmp']['port'])))
)

# SNMPv3/USM setup

# user: usr-md5-none, auth: MD5, priv NONE
config.addV3User(
    snmpEngine, 'usr-md5-none',
    config.usmHMACMD5AuthProtocol, 'authkey1'
)
# Allow full MIB access for each user at VACM
config.addVacmUser(snmpEngine, 3, 'usr-md5-none', 'authNoPriv', (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))


# SNMPv2c setup

# SecurityName <-> CommunityName mapping.
config.addV1System(snmpEngine, 'my-area', 'public')

# Allow full MIB access for this user / securityModels at VACM
config.addVacmUser(snmpEngine, 2, 'my-area', 'noAuthNoPriv', (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))

# Get default SNMP context this SNMP engine serves
snmpContext = context.SnmpContext(snmpEngine)


# Create an SNMP context with default ContextEngineId (same as SNMP engine ID)
snmpContext = context.SnmpContext(snmpEngine)

mibBuilder = snmpContext.getMibInstrum().getMibBuilder()

MibScalar, MibScalarInstance = mibBuilder.importSymbols(
    'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance'
)
class MyStaticMibScalarInstance(MibScalarInstance):
    def getValue(self, name, idx):
        currentDT = datetime.datetime.now()
        return self.getSyntax().clone(
            'Hello World!! It\'s currently: ' + str(currentDT)
        )

class AnotherStaticMibScalarInstance(MibScalarInstance):
    def getValue(self, name, idx):
        return self.getSyntax().clone('Ahoy hoy?')

###OID 1.0.0.0
class AIR_hss_imsi_known_check_SQL_Fail(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('AIR_hss_imsi_known_check_SQL_Fail'))
        except:
            return self.getSyntax().clone(0)
    

###OID 2.0.0.0
class AIR_hss_imsi_known_check_IMSI_unattached_w_SIM(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('AIR_hss_imsi_known_check_IMSI_unattached_w_SIM'))
        except:
            return self.getSyntax().clone(0)
    

###OID 3.0.0.0
class AIR_hss_imsi_known_check_IMSI_Blocked(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('AIR_hss_imsi_known_check_IMSI_Blocked'))
        except:
            return self.getSyntax().clone(0)
    

###OID 4.0.0.0
class AIR_hss_get_subscriber_data_v2_v2_IMSI_Blocked(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('AIR_hss_get_subscriber_data_v2_v2_IMSI_Blocked'))
        except:
            return self.getSyntax().clone(0)
    

###OID 5.0.0.0
class AIR_general(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('AIR_general'))
        except:
            return self.getSyntax().clone(0)
    

###OID 6.0.0.0
class generate_avp_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('generate_avp_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 7.0.0.0
class generate_vendor_avp(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('generate_vendor_avp'))
        except:
            return self.getSyntax().clone(0)
    

###OID 8.0.0.0
class diameter_packet_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('diameter_packet_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 9.0.0.0
class diameter_packet_decode_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('diameter_packet_decode_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 10.0.0.0
class diameter_decode_avp_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('diameter_decode_avp_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.0.257.0
class Answer_257_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_257_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.0.257.1
class Answer_257_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_257_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.0.280.0
class Answer_280_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_280_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.0.280.1
class Answer_280_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_280_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.0.282.0
class Answer_282_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_282_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.0.282.1
class Answer_282_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_282_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777251.316.0
class Answer_16777251_316_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777251_316_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777251.316.1
class Answer_16777251_316_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777251_316_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777251.318.0
class Answer_16777251_318_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777251_318_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 11.0.0.0
class S6a_user_unknown_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('S6a_user_unknown_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 12.0.0.0
class S6a_resync_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('S6a_resync_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777251.318.1
class Answer_16777251_318_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777251_318_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777251.321.0
class Answer_16777251_321_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777251_321_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777251.321.1
class Answer_16777251_321_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777251_321_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777251.323.0
class Answer_16777251_323_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777251_323_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777251.323.1
class Answer_16777251_323_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777251_323_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777238.272.0
class Answer_16777238_272_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777238_272_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777238.272.1
class Answer_16777238_272_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777238_272_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.300.0
class Answer_16777216_300_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_300_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.300.1
class Answer_16777216_300_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_300_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.301.0
class Answer_16777216_301_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_301_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.301.1
class Answer_16777216_301_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_301_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.302.0
class Answer_16777216_302_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_302_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.302.1
class Answer_16777216_302_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_302_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.303.0
class Answer_16777216_303_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_303_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.303.1
class Answer_16777216_303_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_303_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.304.0
class Answer_16777216_304_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_304_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777216.304.1
class Answer_16777216_304_success_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777216_304_success_count'))
        except:
            return self.getSyntax().clone(0)
    

###OID 0.16777252.324.0
class Answer_16777252_324_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('Answer_16777252_324_attempt_count'))
        except:
            return self.getSyntax().clone(0)
    


mibBuilder.exportSymbols(
    '__MY_MIB', MibScalar((1, 3, 6, 1, 2, 1, 1, 1), v2c.OctetString()),
            AIR_hss_imsi_known_check_SQL_Fail((1, 3, 6, 1, 2, 1, 1, 1), (1, 0, 0, 0), v2c.Integer32()),
        AIR_hss_imsi_known_check_IMSI_unattached_w_SIM((1, 3, 6, 1, 2, 1, 1, 1), (2, 0, 0, 0), v2c.Integer32()),
        AIR_hss_imsi_known_check_IMSI_Blocked((1, 3, 6, 1, 2, 1, 1, 1), (3, 0, 0, 0), v2c.Integer32()),
        AIR_hss_get_subscriber_data_v2_v2_IMSI_Blocked((1, 3, 6, 1, 2, 1, 1, 1), (4, 0, 0, 0), v2c.Integer32()),
        AIR_general((1, 3, 6, 1, 2, 1, 1, 1), (5, 0, 0, 0), v2c.Integer32()),
        generate_avp_count((1, 3, 6, 1, 2, 1, 1, 1), (6, 0, 0, 0), v2c.Integer32()),
        generate_vendor_avp((1, 3, 6, 1, 2, 1, 1, 1), (7, 0, 0, 0), v2c.Integer32()),
        diameter_packet_count((1, 3, 6, 1, 2, 1, 1, 1), (8, 0, 0, 0), v2c.Integer32()),
        diameter_packet_decode_count((1, 3, 6, 1, 2, 1, 1, 1), (9, 0, 0, 0), v2c.Integer32()),
        diameter_decode_avp_count((1, 3, 6, 1, 2, 1, 1, 1), (10, 0, 0, 0), v2c.Integer32()),
        Answer_257_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 0, 257, 0), v2c.Integer32()),
        Answer_257_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 0, 257, 1), v2c.Integer32()),
        Answer_280_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 0, 280, 0), v2c.Integer32()),
        Answer_280_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 0, 280, 1), v2c.Integer32()),
        Answer_282_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 0, 282, 0), v2c.Integer32()),
        Answer_282_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 0, 282, 1), v2c.Integer32()),
        Answer_16777251_316_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777251, 316, 0), v2c.Integer32()),
        Answer_16777251_316_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777251, 316, 1), v2c.Integer32()),
        Answer_16777251_318_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777251, 318, 0), v2c.Integer32()),
        S6a_user_unknown_count((1, 3, 6, 1, 2, 1, 1, 1), (11, 0, 0, 0), v2c.Integer32()),
        S6a_resync_count((1, 3, 6, 1, 2, 1, 1, 1), (12, 0, 0, 0), v2c.Integer32()),
        Answer_16777251_318_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777251, 318, 1), v2c.Integer32()),
        Answer_16777251_321_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777251, 321, 0), v2c.Integer32()),
        Answer_16777251_321_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777251, 321, 1), v2c.Integer32()),
        Answer_16777251_323_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777251, 323, 0), v2c.Integer32()),
        Answer_16777251_323_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777251, 323, 1), v2c.Integer32()),
        Answer_16777238_272_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777238, 272, 0), v2c.Integer32()),
        Answer_16777238_272_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777238, 272, 1), v2c.Integer32()),
        Answer_16777216_300_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 300, 0), v2c.Integer32()),
        Answer_16777216_300_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 300, 1), v2c.Integer32()),
        Answer_16777216_301_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 301, 0), v2c.Integer32()),
        Answer_16777216_301_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 301, 1), v2c.Integer32()),
        Answer_16777216_302_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 302, 0), v2c.Integer32()),
        Answer_16777216_302_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 302, 1), v2c.Integer32()),
        Answer_16777216_303_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 303, 0), v2c.Integer32()),
        Answer_16777216_303_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 303, 1), v2c.Integer32()),
        Answer_16777216_304_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 304, 0), v2c.Integer32()),
        Answer_16777216_304_success_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777216, 304, 1), v2c.Integer32()),
        Answer_16777252_324_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0, 16777252, 324, 0), v2c.Integer32())
)

# Register SNMP Applications at the SNMP engine for particular SNMP context
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

# Register an imaginary never-ending job to keep I/O dispatcher running forever
snmpEngine.transportDispatcher.jobStarted(1)

# Run I/O dispatcher which would receive queries and send responses
try:
    snmpEngine.transportDispatcher.runDispatcher()

except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise