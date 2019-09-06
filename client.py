#Interactive Diameter Client
import socket
import sys
import diameter

#hostname = input("Host to connect to:\t")
#domain = input("Domain:\t")
hostname = "localhost"
domain = "localdomain"

supported_calls = ["CER", "DWR"]


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
                if input("Print AVPs (Y/N):\t") == "Y":
                    for avp in avps:
                        print("\t\t" + str(avp))
                        
    except Exception as e:
        print("failed to get all return data - Error " + str(e))
        

while True:
    print("\n\nQuerying Diameter peer " + str(hostname) + " of domain " + str(domain))
    request = input("Enter request type:\t")

    if request == "CER":
        print("Sending Cabailites Exchange Request to " + str(hostname))
        SendRequest(diameter.Request_257())
    elif request == "DWR":
        print("Sending Device Watchdog Request to " + str(hostname))
        SendRequest(diameter.Request_280())
    else:
        print("Invalid input, valid entries are:")
        for keys in supported_calls:
            print(keys)
