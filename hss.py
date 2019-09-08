import sys
import socket
import diameter
import binascii
import time
from threading import Thread, Lock
import os

diameter = diameter.Diameter('nick-pc.localdomain', 'localdomain', 'PyHSS')

def on_new_client(clientsocket,client_address):
    print('New connection from ' + str(client_address))
    data_sum = b''
    firstloop = 0
    while True:
        try:
            data = clientsocket.recv(32)
            
            if not data:
                print("Connection closed by " + str(client_address))
                break
                        
            packet_length = diameter.decode_diameter_packet_length(data)            #Calculate length of packet from start of packet
            data_sum = data + clientsocket.recv(packet_length - 32)                 #Recieve remainder of packet from buffer
            packet_vars, avps = diameter.decode_diameter_packet(data_sum)           #Decode packet into array of AVPs and Dict of Packet Variables (packet_vars)


            #Send Capabilities Exchange Answer (CEA) response to Capabilites Exchange Request (CER)
            if packet_vars['command_code'] == 257 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":                    
                print("Received Request with command code 257 (CER) from " + str(client_address) + "\n\tSending response (CEA)")
                response = diameter.Answer_257(packet_vars, avps)                   #Generate Diameter packet
                clientsocket.sendall(bytes.fromhex(response))                       #Send it


            #Send Credit Control Answer (CCA) response to Credit Control Request (CCR)
            elif packet_vars['command_code'] == 272 and packet_vars['ApplicationId'] == 16777238:
                print("Received 3GPP Credit-Control-Request from " + str(client_address) + "\n\tGenerating (CCA)")
                response = diameter.Answer_16777238_272(packet_vars, avps)          #Generate Diameter packet
                clientsocket.sendall(bytes.fromhex(response))                       #Send it


            #Send Device Watchdog Answer (DWA) response to Device Watchdog Requests (DWR)
            elif packet_vars['command_code'] == 280 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                print("Received Request with command code 280 (DWR) from " + str(client_address) + "\n\tSending response (DWA)")
                response = diameter.Answer_280(packet_vars, avps)                   #Generate Diameter packet
                clientsocket.sendall(bytes.fromhex(response))                       #Send it


            #Send Disconnect Peer Answer (DPA) response to Disconnect Peer Request (DPR)
            elif packet_vars['command_code'] == 282 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                print("Received Request with command code 282 (DPR) from " + str(client_address) + "\n\tForwarding request...")
                response = diameter.Answer_282(packet_vars, avps)               #Generate Diameter packet
                clientsocket.sendall(bytes.fromhex(response))                   #Send it


            #S6a Authentication Information Answer (AIA) response to Authentication Information Request (AIR)
            elif packet_vars['command_code'] == 318 and packet_vars['ApplicationId'] == 16777251 and packet_vars['flags'] == "c0":
                print("Received Request with command code 318 (3GPP Authentication-Information-Request) from " + str(client_address) + "\n\tGenerating (AIA)")
                print(packet_vars)
                response = diameter.Answer_16777251_318(packet_vars, avps)      #Generate Diameter packet
                clientsocket.sendall(bytes.fromhex(response))                   #Send it

            #S6a Update Location Answer (ULA) response to Update Location Request (ULR)
            elif packet_vars['command_code'] == 316 and packet_vars['ApplicationId'] == 16777251:
                print("Received Request with command code 316 (3GPP Update Location-Request) from " + str(client_address) + "\n\tGenerating (ULA)")
                response = diameter.Answer_16777251_316(packet_vars, avps)      #Generate Diameter packet
                clientsocket.sendall(bytes.fromhex(response))                   #Send it

            #Cx Multimedia Authentication Request (Unfinished)
            elif packet_vars['command_code'] == 303 and packet_vars['ApplicationId'] == 16777216:
                print("Received Request with command code 303 (3GPP Multimedia Authentication Request) from " + str(client_address) + "\n\tGenerating (ULA)")
                response = diameter.Answer_16777216_303(packet_vars, avps)      #Generate Diameter packet
                print(response)
                clientsocket.sendall(bytes.fromhex(response))                   #Send it



            else:
                print("Recieved packet with Command Code: " + str(packet_vars['command_code']) + ", ApplicationID: " + str(packet_vars['ApplicationId']) + " and flags " + str(packet_vars['flags']))
                for keys in packet_vars:
                    print(keys)
                    print("\t" + str(packet_vars[keys]))
                print(avps)
                print("Panicking and exiting")
                clientsocket.close()
                sys.exit()
                
        except KeyboardInterrupt:
            #Clean up the connection on keyboard interupt
            response = diameter.Request_282()                       #Generate Disconnect Peer Request Diameter packet
            clientsocket.sendall(bytes.fromhex(response))             #Send it
            clientsocket.close()
            print("Connection closed")
            sys.exit()
    



# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('0.0.0.0', 3868)


sock.bind(server_address)
print('PyHSS listening on port ' + str(server_address[1]))

# Listen for up to 1 incoming connection
sock.listen(1)

while True:
    # Wait for a connection
    print('\nWaiting for a connection...')
    connection, client_address = sock.accept()
    t=Thread(target=on_new_client, args=(connection,client_address))
    t.start()
    #_thread.start_new_thread(on_new_client,(connection,client_address))

