#Interactive Diameter Client
import socket
import sys
import os
import diameter
import time
import _thread
global recv_ip
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

if transport == "TCP":
    clientsocket = socket.socket()
    clientsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    
    clientsocket.bind((recv_ip[0], 1024))
elif transport == "SCTP":
    import sctp
    clientsocket = sctp.sctpsocket_tcp(socket.AF_INET)
else:
    print(str(transport) + " is not valid transport type, exiting.")
    sys.exit()

print("Connecting to " + str(hostname))
try:
    clientsocket.connect((hostname,3868))
except Exception as e:
    print("Failed to connect to server - Error: " + str(e))
    sys.exit()


def ReadBuffer(): 
    while True:
        try:
                data = clientsocket.recv(32)
                packet_length = diameter.decode_diameter_packet_length(data)            #Calculate length of packet from start of packet
                data_sum = data + clientsocket.recv(packet_length - 32)                 #Recieve remainder of packet from buffer
                packet_vars, avps = diameter.decode_diameter_packet(data_sum)
                if  int(packet_vars['command_code']) == 280 and diameter.hex_to_bin(packet_vars['flags'])[0] == "1":  # Recieve DWR ,send DWA
                    print("Recieved DWR - Sending DWA to " +str(hostname) )
                    SendRequest(diameter.Answer_280(packet_vars, avps))
                    continue
                print("Got response from " + str(hostname))
                for keys in packet_vars:
                    print("\t" + str(keys) + "\t" + str(packet_vars[keys]))

                print("Command Code: " + str(packet_vars['command_code']))
                if int(packet_vars['command_code']) == 280:
                    flags_bin = diameter.hex_to_bin(packet_vars['flags'])
                    print("Flags are " + str(flags_bin)) 
                    print("Recieved DWA")
                if int(packet_vars['command_code']) == 257:
                    #Check if Request or Response
                    flags_bin = diameter.hex_to_bin(packet_vars['flags'])
                    print("Flags are " + str(flags_bin)) 
                    #ToDo - check first byte only
                    if flags_bin[0] == '1':
                        print("Recieved CER - Sending CEA")
                        SendRequest(diameter.Answer_257(packet_vars, avps, recv_ip))
                    else:
                        print("Is CEA")
                        
                    
                if input("Print AVPs (Y/N):\t") == "Y":
                    for avp in avps:
                        print("\t\t" + str(avp))
        except KeyboardInterrupt:
            print("User exited background loop")
            break                       
        except Exception as e:
            time.sleep(0.1)
            continue

def SendRequest(request):
    clientsocket.sendall(bytes.fromhex(request))
    #ReadBuffer()

_thread.start_new_thread(ReadBuffer,())
while True:
    print("\n\nQuerying Diameter peer " + str(hostname))
    print("Note - You may need to exchange a CER before doing anything fun")
    request = input("Enter request type:\t")

    if request == "R":
        print("Selected Readbuffer mode - Automatically listening for DWR and responding DWA")
        print("To exit this mode press Control + C once and wait, loop exit will happen at end of the loop.")
        ReadBuffer()
    elif request == "CER":
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
        SendRequest(diameter.Request_16777251_317(imsi, DestinationHost, DestinationRealm))        
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
