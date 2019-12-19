#Interactive Diameter Client
import socket
import sys
import diameter

#hostname = input("Host to connect to:\t")
#domain = input("Domain:\t")
hostname = "localhost"
realm = "open-ims.test"

supported_calls = ["CER", "DWR", "AIR", "ULR", "UAR", "MAR"]

diameter = diameter.Diameter('client.localdomain', 'localdomain', 'PyHSS-client')

clientsocket = socket.socket()
try:
    clientsocket.connect((hostname,3868))
except Exception as e:
    print("Failed to connect to server - Error: " + str(e))
    sys.exit()


def SendRequest(request):

    clientsocket.sendall(bytes.fromhex(request))
    try:
                data = clientsocket.recv(32)
                packet_length = diameter.decode_diameter_packet_length(data)            #Calculate length of packet from start of packet
                data_sum = data + clientsocket.recv(packet_length - 32)                 #Recieve remainder of packet from buffer
                packet_vars, avps = diameter.decode_diameter_packet(data_sum) 
                print("Got response from " + str(hostname))
                for keys in packet_vars:
                    print("\t" + str(keys) + "\t" + str(packet_vars[keys]))

                for avp in avps:
                    print(avp['avp_code'])
                    if int(avp['avp_code']) == 318:
                        print("Received Authentication Information Answer - Store output of Crypto vectors?")
                        file.open("vectors.txt", "w")
                        file.write(avp['misc_data'])
                        file.close()
                    
                if input("Print AVPs (Y/N):\t") == "Y":
                    for avp in avps:
                        print("\t\t" + str(avp))
                        
    except Exception as e:
        print("failed to get all return data - Error " + str(e))
        

while True:
    print("\n\nQuerying Diameter peer " + str(hostname) + " of domain " + str(realm))
    print("Note - You may need to exchange a CER before doing anything fun")
    request = input("Enter request type:\t")

    if request == "CER":
        print("Sending Cabailites Exchange Request to " + str(hostname))
        SendRequest(diameter.Request_257())
    elif request == "DWR":
        print("Sending Device Watchdog Request to " + str(hostname))
        SendRequest(diameter.Request_280())
    elif request == "ULR":
        imsi = str(input("IMSI:\t"))
        print("Sending Update Location Request to " + str(hostname))
        SendRequest(diameter.Request_16777251_316(imsi))
    elif request == "AIR":
        imsi = str(input("IMSI:\t"))
        print("Sending Authentication Information Request to " + str(hostname))
        SendRequest(diameter.Request_16777251_318(imsi))
    elif request == "UAR":
        imsi = '214010000000001'
        domain = 'open-ims.test'
        print("Sending User Authentication Request to " + str(hostname))
        SendRequest(diameter.Request_16777216_300(imsi, domain))
    elif request == "MAR":
        #imsi = str(input("IMSI:\t"))
        #domain = str(input("Domain:\t"))
        imsi = '214010000000001'
        domain = 'open-ims.test'
        print("Sending Multimedia Authentication Request to " + str(hostname))
        SendRequest(diameter.Request_16777216_303(imsi, domain))
    else:
        print("Invalid input, valid entries are:")
        for keys in supported_calls:
            print(keys)
