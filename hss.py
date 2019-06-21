import sys
import socket
import diameter
import binascii
import time
import signal
signal.signal(signal.SIGINT, signal.default_int_handler)


# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('0.0.0.0', 3868)

print('listening')
sock.bind(server_address)


# Listen for up to 1 incoming connection
sock.listen(1)

while True:
    # Wait for a connection
    print('Waiting for a connection...')
    connection, client_address = sock.accept()


    print('New connection from ' + str(client_address))
    data_sum = b''
    while True:
        try:
            data = connection.recv(32)
            
            if not data:
                print("Connection closed by " + str(client_address))
                break
                        
            packet_length = diameter.decode_diameter_packet_length(data)    #Calculate length of packet from start of packet
            data_sum = data + connection.recv(packet_length - 32)           #Recieve remainder of packet from buffer
            packet_vars, avps = diameter.decode_diameter_packet(data_sum)   #Decode packet into array of AVPs and Dict of Packet Variables (packet_vars)

            #Send Capabilities Exchange Answer (CEA) response to Capabilites Exchange Request (CER)
            if packet_vars['command_code'] == 257 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                print("Received Request with command code 257 (CER) from " + str(client_address) + "\n\tSending response (CEA)")
                response = diameter.Answer_257(packet_vars, avps)   #Generate Diameter packet
                connection.sendall(bytes.fromhex(response))         #Send it

            #Send Device Watchdog Answer (DWA) to Device Watchdog Requests (DWR)
            elif packet_vars['command_code'] == 280 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                print("Received Request with command code 280 (DWR) from " + str(client_address) + "\n\tSending response (DWA)")
                response = diameter.Answer_280(packet_vars, avps)   #Generate Diameter packet
                connection.sendall(bytes.fromhex(response))         #Send it

##                time.sleep(1)
##                request = diameter.Request_16777251_318()
##                connection.sendall(bytes.fromhex(request))


            #Send Disconnect Peer Answer (DPA) to Disconnect Peer Request (DPR)
            elif packet_vars['command_code'] == 282 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                print("Received Request with command code 282 (DPR) from " + str(client_address) + "\n\tSending response (DWA)")
                response = diameter.Answer_282(packet_vars, avps)   #Generate Diameter packet
                connection.sendall(bytes.fromhex(response))         #Send it


            else:
                print("Recieved packet with Command Code: " + str(packet_vars['command_code']) + ", ApplicationID: " + str(packet_vars['ApplicationId']) + " and flags " + str(packet_vars['flags']))
                for keys in packet_vars:
                    print(keys)
                    print("\t" + str(packet_vars[keys]))
                print(avps)
                print("Panicking and exiting")
                connection.close()
                sys.exit()
                
        except KeyboardInterrupt:
            #Clean up the connection on keyboard interupt
            response = diameter.Request_282()                       #Generate Disconnect Peer Request Diameter packet
            connection.sendall(bytes.fromhex(response))             #Send it
            connection.close()
            print("Connection closed")
            sys.exit()
    
