#Allows sending of Diameter commands to a Diameter client connected to the HSS
import os
import sys
import inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir) 
import yaml
with open('config.yaml') as stream:
    yaml_config = (yaml.safe_load(stream))
import json
import redis
import diameter
import time
import yaml
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

#Values to change / tweak
recv_ip = yaml_config['hss']['bind_ip']                                                         #IP of this Machine
diameter_host = yaml_config['hss']['OriginHost']                                                        #Diameter Host of this Machine
realm = yaml_config['hss']['OriginRealm']                                          #Diameter Realm of this machine
DestinationHost = ""                                             #Diameter Host of Destination
DestinationRealm = input("Enter Diameter Realm: ")                                                #Diameter Realm of Destination
hostname = input("Enter IP of Diameter Peer to connect to: ")                                                         #IP of Remote Diameter Host
mcc = yaml_config['hss']['MCC']                                                                     #Mobile Country Code
mnc = yaml_config['hss']['MNC']                                                                      #Mobile Network Code
transport = yaml_config['hss']['transport']                                                              #Transport Type - TCP or SCTP (SCTP Support is basic)

diameter = diameter.Diameter(diameter_host, realm, 'PyHSS-client', str(mcc), str(mnc))

supported_calls = ["CER", "DWR", "AIR", "ULR", "UAR", "PUR", "SAR", "MAR", "MCR", "LIR", "RIR", "CLR", "NOR", "DEP", "UDR"]

r = redis.Redis(host=str(yaml_config['redis']['host']), port=str(yaml_config['redis']['port']), db=0)

print("\n\nDiameter Peers:")
ActivePeerDict = r.get('ActivePeerDict')
print("ActivePeerDict: " + str(ActivePeerDict))
if ActivePeerDict == None:
    print("No connected peers. Exiting.")
    sys.exit()
elif len(ActivePeerDict) == 0:
    print("No connected peers. Exiting.")
    sys.exit()
ActivePeerDict = json.loads(ActivePeerDict)

for keys in ActivePeerDict:
    print(keys)
    for subkeys in ActivePeerDict[keys]:
        print("\t" + str(subkeys) + ": \t" + str(ActivePeerDict[keys][subkeys]))
    print('\n')
DiameterHostname = input("Enter DiameterHostname to send Request to: ")

def SendRequest(request):
    print("Writing request to Queue '" + str(DiameterHostname)  + "_request_queue'")
    r.hset(str(DiameterHostname) + "_request_queue", "hss_Async_client_" + str(int(time.time())), request)
    print("Written to Queue to send.")

hostname = DiameterHostname
print("Sending Request to connected Diameter peer " + str(hostname))
request = input("Enter request type:\t")
if request == "CER":
    print("Sending Cabailites Exchange Request to " + str(hostname))
    SendRequest(diameter.Request_257())
elif request == "DWR":
    print("Sending Device Watchdog Request to " + str(hostname))
    SendRequest(diameter.Request_280())
elif request == "DPR":
    print("Sending Disconnect Peer Request to " + str(hostname))
    SendRequest(diameter.Request_282())
    sys.exit()
elif request == "ULR":
    imsi = str(input("IMSI:\t"))
    print("Sending Update Location Request to " + str(hostname))
    SendRequest(diameter.Request_16777251_316(imsi, DestinationRealm))
elif request == "CLR":
    imsi = str(input("IMSI:\t"))
    print("Sending Cancel Location Request to " + str(hostname))
    SendRequest(diameter.Request_16777251_317(imsi, DestinationRealm, DestinationHost))
elif request == "AIR":
    imsi = str(input("IMSI:\t"))
    requested_vectors = str(input("Number of Vectors:\t"))
    print("Sending Authentication Information Request to " + str(hostname))
    SendRequest(diameter.Request_16777251_318(imsi, DestinationHost, DestinationRealm))
elif request == "UAR":
    imsi = str(input("IMSI:\t"))
    domain = str(input("Domain:\t"))
    print("Sending User Authentication Request to " + str(hostname))
    SendRequest(diameter.Request_16777216_300(imsi, domain))
elif request == "PUR":
    imsi = str(input("IMSI:\t"))
    print("Sending User Purge Request to " + str(hostname))
    SendRequest(diameter.Request_16777251_321(imsi, DestinationHost, DestinationRealm))
elif request == "NOR":
    imsi = str(input("IMSI:\t"))
    print("Sending NOtify Request to " + str(hostname))
    SendRequest(diameter.Request_16777251_323(imsi, DestinationHost, DestinationRealm))
elif request == "DEP":
    imsi = str(input("IMSI:\t"))
    print("Sending Diameter-EAP Request to " + str(hostname))
    SendRequest(diameter.Request_16777264_268(imsi, DestinationHost, DestinationRealm))        
elif request == "SAR":
    imsi = str(input("IMSI:\t"))
    domain = str(input("Domain:\t"))
    print("Sending Server Assignment Request to " + str(hostname))
    SendRequest(diameter.Request_16777216_301(imsi, domain))
elif request == "MAR":
    imsi = str(input("IMSI:\t"))
    domain = str(input("Domain:\t"))
    print("Sending Multimedia Authentication Request to " + str(hostname))
    SendRequest(diameter.Request_16777216_303(imsi, domain))
elif request == "MCR":
    imsi = str(input("IMSI:\t"))
    imei = str(input("IMEI:\t"))
    software_version = str(input("ME Software Version:\t"))
    print("Sending ME-Identity-Check Request " + str(hostname))
    SendRequest(diameter.Request_16777252_324(imsi, imei, software_version))
elif request == "RTR":
    imsi = str(input("IMSI:\t"))
    domain = str(input("Domain:\t"))
    print("Sending Registration Termination Request to " + str(hostname))
    SendRequest(diameter.Request_16777216_304(imsi, domain))
elif request == "LIR":
    msisdn = str(input("MSISDN:\t"))
    sipaor = "sip:" + str(msisdn)
    print("Sending Location-Information Request to " + str(hostname))
    SendRequest(diameter.Request_16777216_285(sipaor))
elif request == "UDR":
    msisdn = str(input("MSISDN:\t"))
    print("Sending User-Data Request to " + str(hostname))
    SendRequest(diameter.Request_16777217_306(msisdn))        
elif request == "RIR":
    imsi = str(input("IMSI:\t"))
    if len(imsi) != 0:
        print("Sending LCS Routing Information Request with IMSI to " + str(hostname))
        SendRequest(diameter.Request_16777291_8388622(imsi=imsi))
    else:
        msisdn = str(input("MSISDN:\t"))
        print("Sending LCS Routing Information Request with MSISDN to " + str(hostname))
        SendRequest(diameter.Request_16777291_8388622(msisdn=msisdn))
else:
    print("Invalid input, valid entries are:")
    for keys in supported_calls:
        print(keys)
