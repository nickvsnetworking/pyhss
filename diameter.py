#Diameter Packet Crafter
import socket
import sys
import binascii
import math

def myround(n, base=4):
    if(n > 0):
        return math.ceil(n/4.0) * 4;
    elif( n < 0):
        return math.floor(n/4.0) * 4;
    else:
        return 4;

def ip_to_hex(ip):
    ip = ip.split('.')
    ip_hex = "0001"         #Only works for IPv4
    ip_hex = ip_hex + str(format(int(ip[0]), 'x').zfill(2))
    ip_hex = ip_hex + str(format(int(ip[1]), 'x').zfill(2))
    ip_hex = ip_hex + str(format(int(ip[2]), 'x').zfill(2))
    ip_hex = ip_hex + str(format(int(ip[3]), 'x').zfill(2))
    return ip_hex


def string_to_hex(string):
    
    string_bytes = string.encode('utf-8')
    return str(binascii.hexlify(string_bytes), 'ascii')


def generate_avp(avp_code, avp_flags, avp_content):
    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
    #print("Generating AVP")

    #print("\tAVP Code:   " + str(avp_code))
    avp_code = format(avp_code,"x").zfill(8)
    

    #print("\tAVP Flags:  " + str(avp_flags))

    avp_length = 1 ##This is a placeholder that's overwritten later

    #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
    avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_content)
    avp_length = int(len(avp)/2)
    #print("\tAVP Length: " + str(avp_length))

    if avp_length % 4  == 0:
        #print("Multiple of 4 - No Padding needed")
        avp_padding = ''
    else:
        #print("Not multiple of 4 - Padding needed")
        rounded_value = myround(avp_length)
        #print("Rounded value is " + str(rounded_value))
        #print("Has " + str( int( rounded_value - avp_length)) + " bytes of padding")
        avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)

    #print("\tAVP Padding: " + str(avp_padding))
    
    avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_content) + str(avp_padding)
    #print("\tAVP Data   :" + str(avp) + '\n')
    return avp

    



def generate_diameter_packet(packet_version, packet_flags, packet_command_code, packet_application_id, packet_hop_by_hop_id, packet_end_to_end_id, avp):
    #Placeholder that is updated later on
    packet_length = 228
    packet_length = format(packet_length,"x").zfill(6)

    #print("Generating Diamter Packet")
    
    #print("\tPacket Flags       : " + str(packet_flags))

    
    packet_command_code = format(packet_command_code,"x").zfill(6)
    #print("\tPacket Command Code: " + str(packet_command_code))

    
    packet_application_id = format(packet_application_id,"x").zfill(8)
    #print("\tPacket Application ID: " + str(packet_application_id))

    
    packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
    packet_length = int(round(len(packet_hex))/2)
    #print("\tPacket Length: " + str(packet_length))
    packet_length = format(packet_length,"x").zfill(6)
    
    packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
    #print("\tPacket Bytes over the wire are: " + packet_hex  + '\n')
    return packet_hex




def decode_diameter_packet(data):
    packet_vars = {}
    avps = []
    #print(data)
    #print(type(data))
    data = data.hex()

    packet_vars['packet_version'] = data[0:2]
    packet_vars['length'] = int(data[2:8], 16)
    packet_vars['flags'] = data[8:10]       
    packet_vars['command_code'] = int(data[10:16], 16)
    packet_vars['ApplicationId'] = int(data[16:24], 16)
    packet_vars['hop-by-hop-identifier'] = data[24:32]
    packet_vars['end-to-end-identifier'] = data[32:40]

    avp_sum = data[40:]

    #print("Decoded Diameter values are:" )
    for keys in packet_vars:
        #print("\t" + keys + "\t" + str(packet_vars[keys]) + "\t(" + str(type(packet_vars[keys])) + ")")
        pass
    avp_vars, remaining_avps = decode_avp_packet(avp_sum)
    avps.append(avp_vars)
    #print("Length of remaining AVPs is: " + str(len(remaining_avps)))
    while len(remaining_avps) > 0:
        avp_vars, remaining_avps = decode_avp_packet(remaining_avps)
        avps.append(avp_vars)
    else:
        #print("Complete - Decoded all AVPs in Diameter Packet")
        pass

    return packet_vars, avps

def decode_avp_packet(data):
    avp_vars = {}
    #print("Recieved AVP raw is: " + str(data))
    avp_vars['avp_code'] = int(data[0:8], 16)
    avp_vars['avp_flags'] = data[8:10]
    avp_vars['avp_length'] = int(data[10:16], 16)
    #print(avp_vars['avp_length'])
    avp_vars['misc_data'] = data[16:(avp_vars['avp_length']*2)]
    if avp_vars['avp_length'] % 4  == 0:
        #print("Multiple of 4 - No Padding needed")
        avp_vars['padding'] = 0
    else:
        #print("Not multiple of 4 - Padding needed")
        rounded_value = myround(avp_vars['avp_length'])
        #print("Rounded value is " + str(rounded_value))
        #print("Has " + str( int( rounded_value - avp_vars['avp_length'])) + " bytes of padding")
        avp_vars['padding'] = int( rounded_value - avp_vars['avp_length']) * 2
    avp_vars['padded_data'] = data[(avp_vars['avp_length']*2):(avp_vars['avp_length']*2)+avp_vars['padding']]

    #print("Decoded AVP values are:" )
    for keys in avp_vars:
        #print("\t" + keys + "\t" + str(avp_vars[keys]) + "\t" + str(type(avp_vars[keys])))
        pass


    remaining_avps = data[(avp_vars['avp_length']*2)+avp_vars['padding']:]  #returns remaining data in avp string back for processing again

    return avp_vars, remaining_avps


def decode_diameter_packet_length(data):
    packet_vars = {}
    avps = []
    data = data.hex()

    packet_vars['packet_version'] = data[0:2]
    packet_vars['length'] = int(data[2:8], 16)
    if packet_vars['packet_version'] == "01":
        return packet_vars['length']
    else:
        return False


def AVP_278_Origin_State_Incriment(avps):
    for avp_dicts in avps:
        if avp_dicts['avp_code'] == 278:
            origin_state_incriment_int = int(avp_dicts['misc_data'], 16)
            origin_state_incriment_int = origin_state_incriment_int + 1
            origin_state_incriment_hex = format(origin_state_incriment_int,"x").zfill(8)
            return origin_state_incriment_hex
