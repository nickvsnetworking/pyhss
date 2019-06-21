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


# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()


    print('connection from' + str(client_address))
    data_sum = b''
    # Receive the data in small chunks and retransmit it
    while True:
        try:
            data = connection.recv(32)
            packet_length = diameter.decode_diameter_packet_length(data)
            data_sum = data + connection.recv(packet_length - 32)

            if data == 7:       #I don't really remember what this part is about...
                print("Data is equal to 7???")
                data_sum = data_sum + data
                pass
            else:
                packet_vars, avps = diameter.decode_diameter_packet(data_sum)
                

                #Send CEA response to CER
                if packet_vars['command_code'] == 257 and packet_vars['ApplicationId'] == 0:
                    print("Received Request with command code 257 (CER) from " + str(client_address))
                    #Generate AVPs
                    print("\tSending response code 257 (CEA) to " + str(client_address))
                    #Generate Diameter packet
                    response = diameter.Answer_257(packet_vars, avps)
                    #Send it
                    connection.sendall(bytes.fromhex(response))

                #Send Device Watchdog Answer to Device Watchdog Requests
                elif packet_vars['command_code'] == 280 and packet_vars['ApplicationId'] == 0:
                    print("Received Request with command code 280 (DWR) from " + str(client_address))
                    #Generate AVPs
                    print("\tSending response code 280 (DWA) to " + str(client_address))
                    avp = diameter.generate_avp(268, 40, "000007d1")    #Result Code (DIAMETER_SUCESS (2001))
                    avp = avp + diameter.generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localhost'),'ascii')) #Origin Host
                    avp = avp + diameter.generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii')) #Origin Realm
                    avp = avp + diameter.generate_avp(278, 40, diameter.AVP_278_Origin_State_Incriment(avps)) #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
                    #Generate Diameter packet
                    response = diameter.generate_diameter_packet("01", "00", 280, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)
                    #Send it
                    connection.sendall(bytes.fromhex(response))


                #Send Disconnect Peer Answer to Disconnect Peer Request
                elif packet_vars['command_code'] == 282 and packet_vars['ApplicationId'] == 0:
                    print("Received Request with command code 282 (DPR) from " + str(client_address))
                    #Generate AVPs
                    print("\tSending response code 282 (DPA) to " + str(client_address))
                    avp = diameter.generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localhost'),'ascii')) #Origin Host
                    avp = avp + diameter.generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii')) #Origin Realm
                    avp = avp + diameter.generate_avp(268, 40, "000007d1")    #Result Code (DIAMETER_SUCESS (2001))
                    print("AVPs generated")
                    #Generate Diameter packet
                    response = diameter.generate_diameter_packet("01", "00", 282, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)
                    #Send it
                    connection.sendall(bytes.fromhex(response))


                else:
                    print("Recieved packet with Command Code: " + str(packet_vars['command_code']) + " and ApplicationID: " + str(packet_vars['ApplicationId']))
                    print("Panicking and exiting")
                    connection.close()
                    sys.exit()
                    
        except KeyboardInterrupt:
            # Clean up the connection
            connection.close()
            print("Connection closed")
            sys.exit()
    
