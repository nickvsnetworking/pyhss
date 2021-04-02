#Interactive Diameter Client
import socket
import sys
import diameter
import _thread
global recv_ip
recv_ip = "10.9.49.110"
#hostname = input("Host to connect to:\t")
#domain = input("Domain:\t")

hostname = "10.9.49.190"

realm = "mnc001.mcc001.3gppnetwork.org"

supported_calls = ["CER", "DWR", "AIR", "ULR", "UAR", "PUR", "SAR", "MAR", "MCR", "LIR", "RIR"]


diameter = diameter.Diameter('nick-pc', 'mnc001.mcc001.3gppnetwork.org', 'PyHSS-client', '001', '01')
DestinationHost = "hss.localdomain"
DestinationRealm = "localdomain"

clientsocket = socket.socket()
clientsocket.bind((recv_ip, 3871))
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

                for avp in avps:
                    print(avp['avp_code'])
                    if int(avp['avp_code']) == 318:
                        print("Received Authentication Information Answer - Store output of Crypto vectors?")
                        file = open("vectors.txt", "w")
                        file.write(avp['misc_data'])
                        file.close()
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
                        print("Is CEA ")
                        
                    
                if input("Print AVPs (Y/N):\t") == "Y":
                    for avp in avps:
                        print("\t\t" + str(avp))
                        
        except Exception as e:
            print("failed to get all return data - Error " + str(e))

def SendRequest(request):
    clientsocket.sendall(bytes.fromhex(request))
    #ReadBuffer()

_thread.start_new_thread(ReadBuffer,())
while True:
    print("\n\nQuerying Diameter peer " + str(hostname))
    print("Note - You may need to exchange a CER before doing anything fun")
    request = input("Enter request type:\t")

    if request == "R":
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
        SendRequest(diameter.Request_16777251_316(imsi))
    elif request == "AIR":
        imsi = str(input("IMSI:\t"))
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
        SendRequest(diameter.Request_16777251_321(imsi))
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
    elif request == "RIR":
        imsi = str(input("IMSI:\t"))
        print("Sending LCS Routing Information Request to " + str(hostname))
        SendRequest(diameter.Request_16777291_8388622(imsi))
    else:
        print("Invalid input, valid entries are:")
        for keys in supported_calls:
            print(keys)
