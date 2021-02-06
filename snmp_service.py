#Pulled from https://stackoverflow.com/questions/58909285/how-to-add-variable-in-the-mib-tree

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.smi import instrum, builder
from pysnmp.proto.api import v2c
import datetime
import redis


import redis
redis_store = redis.Redis(host='localhost', port=6379, db=0)
# Create SNMP engine
snmpEngine = engine.SnmpEngine()

# Transport setup

# UDP over IPv4
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('127.0.0.1', 1161))
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

# Create multiple independent trees of MIB managed objects (empty so far)
mibTreeA = instrum.MibInstrumController(builder.MibBuilder())
mibTreeB = instrum.MibInstrumController(builder.MibBuilder())

# Register MIB trees at distinct SNMP Context names
snmpContext.registerContextName(v2c.OctetString('context-a'), mibTreeA)
snmpContext.registerContextName(v2c.OctetString('context-b'), mibTreeB)

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

class Answer_280_attempt_count(MibScalarInstance):
    def getValue(self, name, idx):
        return self.getSyntax().clone(redis_store.get('Answer_280_attempt_count'))


mibBuilder.exportSymbols(
    '__MY_MIB', MibScalar((1, 3, 6, 1, 2, 1, 1, 1), v2c.OctetString()),
    MyStaticMibScalarInstance((1, 3, 6, 1, 2, 1, 1, 1), (0,), v2c.OctetString()),
    AnotherStaticMibScalarInstance((1, 3, 6, 1, 2, 1, 1, 1), (0,1), v2c.OctetString()),
    Answer_280_attempt_count((1, 3, 6, 1, 2, 1, 1, 1), (0,2), v2c.Integer32())
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