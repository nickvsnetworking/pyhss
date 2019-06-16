import sys
import socket
import diameter



# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('10.0.1.5', 3868)
print('listening')
sock.bind(server_address) 

# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()

    try:
        print('connection from' + str(client_address))
        data_sum = b''
        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(16)
            print(data)
            if data:
                data_sum = data_sum + data
                pass
            else:
                print("Decoding complete packet: " + str(data_sum))
                packet_vars, avps = diameter.decode_diameter_packet(data_sum)
                print(packet_vars)
                print('\n\n\nno more data from' + str(client_address))
                print("Sending response with Hop-by-Hop Identifier: " + str(packet_vars['hop-by-hop-identifier']))
                print("Sending response with End-to-End Identifier: " + str(packet_vars['end-to-end-identifier']))
                

                avp = diameter.generate_avp(268, 40, "000007d1")    #Result Code
                avp = avp + diameter.generate_avp(264, 40, "7067772e6c6f63616c646f6d61696e") #Origin Host
                avp = avp + diameter.generate_avp(278, 40, "5d00a8a9") #Origin State
                avp = avp + diameter.generate_avp(257, 40, "00017f000003") #Host-IP-Address
                avp = avp + diameter.generate_avp(266, 40, "00000000") #Vendor-Id
                avp = avp + diameter.generate_avp(269, 40, "667265654469616d65746572") #Product-Name
                avp = avp + diameter.generate_avp(267, 40, "000027d9") #Firmware-Revision
                avp = avp + diameter.generate_avp(260, 40, "000001024000000c010000160000010a4000000c000028af") #Vendor-Specific-Application-ID
                avp = avp + diameter.generate_avp(258, 40, "ffffffff") #Auth-Application-ID
                avp = avp + diameter.generate_avp(265, 40, "0000159f") #Supported-Vendor-ID (3GGP v2)
                avp = avp + diameter.generate_avp(265, 40, "000028af") #Supported-Vendor-ID (3GPP)
                avp = avp + diameter.generate_avp(265, 40, "000032db") #Supported-Vendor-ID (ETSI)

                
                response = diameter.generate_diameter_packet("01", "00", 257, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)
                connection.sendall(bytes.fromhex(response))
                break
            
    finally:
        # Clean up the connection
        connection.close()
