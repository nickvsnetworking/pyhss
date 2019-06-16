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

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(16)
            print(data)
            if data:
                pass
            else:
                print('no more data from' + str(client_address))
                print("Sending response")
                avp = str("0000010c4000000c000007d1")
                packet_version = "01"
                packet_flags = "00" #(Proxyable only for flags header)
                packet_command_code = 257
                packet_application_id = 0
                avp = str("0000010c4000000c000007d100000108400000177067772e6c6f63616c646f6d61696e0000000128400000136c6f63616c646f6d61696e00000001164000000c5d00a8a9000001014000000e00017f00000300000000010a4000000c000000000000010d00000014667265654469616d657465720000010b0000000c000027d90000010440000020000001024000000c010000160000010a4000000c000028af000001024000000cffffffff000001094000000c0000159f000001094000000c000028af000001094000000c000032db")
                #avp = diameter.generate_avp(228, 40, "GatewayService-5-1.spjktn002.;1481027351;2178169507", 00)
                response = diameter.generate_diameter_packet(packet_version, packet_flags, packet_command_code, packet_application_id, avp)

                #response = diameter.generate_diameter_packet("01", "00", 257, 0, avp)
                #response = "010000e40000010100000000256aa8348a8511320000010c4000000c000007d100000108400000177067772e6c6f63616c646f6d61696e0000000128400000136c6f63616c646f6d61696e00000001164000000c5d00a8a9000001014000000e00017f00000300000000010a4000000c000000000000010d00000014667265654469616d657465720000010b0000000c000027d90000010440000020000001024000000c010000160000010a4000000c000028af000001024000000cffffffff000001094000000c0000159f000001094000000c000028af000001094000000c000032db"
                #connection.sendall(b'Spain')
                connection.sendall(bytes.fromhex(response))
                break
            
    finally:
        # Clean up the connection
        connection.close()
