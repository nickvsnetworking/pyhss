#Diameter Packet Crafter
import socket
import sys
import binascii



def generate_avp(avp_code, avp_flags, avp_content, avp_padding):
    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    print("Generating AVP")
    avp_code = format(avp_code,"x").zfill(8)
    print("\tAVP Code:   " + str(avp_code))

    print("\tAVP Flags:  " + str(avp_flags))

    avp_length = 255 ##This is a placeholder that's overwritten later

    
    avp_content = binascii.hexlify(avp_content.encode())


    avp_padding = format(avp_padding,"x").zfill(2)
    print("\tAVP Padding: " + str(avp_padding))


    #ToDo - AVP Must always be a multiple of 4 - Round up.
    avp = str(avp_code) + str(avp_flags) + str(avp_length) + str(avp_content.decode("utf-8") + avp_padding)
    avp_length = len(avp)
    print("\tAVP Length: " + str(avp_length))
    avp_length = format(avp_length,"x").zfill(6)
    

    avp = str(avp_code) + str(avp_flags) + str(avp_length) + str(avp_content.decode("utf-8") + avp_padding)
    print("\tAVP Data   :" + str(avp) + '\n')
    return avp

    



def generate_diameter_packet(packet_version, packet_flags, packet_command_code, packet_application_id, avp):
    #Placeholder that is updated later on
    packet_length = 228
    packet_length = format(packet_length,"x").zfill(6)

    print("Generating Diamter Packet")
    
    print("\tPacket Flags       : " + str(packet_flags))

    
    packet_command_code = format(packet_command_code,"x").zfill(6)
    print("\tPacket Command Code: " + str(packet_command_code))

    
    packet_application_id = format(packet_application_id,"x").zfill(8)
    print("\tPacket Application ID: " + str(packet_application_id))


    packet_hop_by_hop_id = str("256aa834")
    packet_end_to_end_id = str("8a851132")

    
    #packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
    #packet_length = len(packet_hex)
    #print("\tPacket Length: " + str(packet_length))
    #packet_length = format(packet_length,"x").zfill(6)
    
    packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
    print("\tPacket Bytes over the wire are: " + packet_hex  + '\n')
    return packet_hex


packet_version = "01"
##packet_flags = "40" #(Proxyable only for flags header)
##packet_command_code = 272
##packet_application_id = 4
###avp = str("000001074000003b47617465776179536572766963652d352d312e73706a6b746e3030322e3b313438313032373335313b3231373831363935303700")
##avp = generate_avp(263, 40, "GatewayService-5-1.spjktn002.;1481027351;2178169507", 00)
##generate_diameter_packet(packet_version, packet_flags, packet_command_code, packet_application_id, avp)
##
##
##
##
