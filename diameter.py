#Diameter Packet Crafter
import socket
import sys
import binascii
import math
import uuid

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


def generate_id(length):
    length = length * 2
    return str(uuid.uuid4().hex[:length])


def generate_avp(avp_code, avp_flags, avp_content):
    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())


    avp_code = format(avp_code,"x").zfill(8)
    
    avp_length = 1 ##This is a placeholder that's overwritten later

    #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
    avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_content)
    avp_length = int(len(avp)/2)

    if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
        avp_padding = ''
    else:                       #Not multiple of 4 - Padding needed
        rounded_value = myround(avp_length)
        #print("Rounded value is " + str(rounded_value))
        #print("Has " + str( int( rounded_value - avp_length)) + " bytes of padding")
        avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)


    
    avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_content) + str(avp_padding)

    return avp

def generate_vendor_avp(avp_code, avp_flags, avp_vendorid, avp_content):
    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())


    avp_code = format(avp_code,"x").zfill(8)
    
    avp_length = 1 ##This is a placeholder that's overwritten later

    avp_vendorid = format(int(avp_vendorid),"x").zfill(8)
    
    #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
    avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_vendorid) + str(avp_content)
    avp_length = int(len(avp)/2)

    if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
        avp_padding = ''
    else:                       #Not multiple of 4 - Padding needed
        rounded_value = myround(avp_length)
        #print("Rounded value is " + str(rounded_value))
        #print("Has " + str( int( rounded_value - avp_length)) + " bytes of padding")
        avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)


    
    avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_vendorid) + str(avp_content) + str(avp_padding)

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
    if avp_vars['avp_flags'] == "c0":
        print("Decoding Vendor AVP")
        avp_vars['vendor_id'] = int(data[16:24], 16)
        avp_vars['misc_data'] = data[24:(avp_vars['avp_length']*2)]
    else:
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


def get_avp_data(avps, avp_code):               #Loops through list of dicts generated by the packet decoder, and returns the data for a specific AVP code in list (May be more than one AVP with same code but different data)
    misc_data = []
    for keys in avps:
        if keys['avp_code'] == avp_code:
            misc_data.append(keys['misc_data'])
    return misc_data


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


def AVP_278_Origin_State_Incriment(avps):                                               #Capabilities Exchange Answer incriment AVP body
    for avp_dicts in avps:
        if avp_dicts['avp_code'] == 278:
            origin_state_incriment_int = int(avp_dicts['misc_data'], 16)
            origin_state_incriment_int = origin_state_incriment_int + 1
            origin_state_incriment_hex = format(origin_state_incriment_int,"x").zfill(8)
            return origin_state_incriment_hex






#### Diameter Answers ####

def Answer_257(packet_vars, avps):
    avp = ''                                                                                    #Initiate empty var AVP 
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))            #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(278, 40, AVP_278_Origin_State_Incriment(avps))                          #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
    avp += generate_avp(257, 40, ip_to_hex("10.0.0.5"))                                         #Host-IP-Address
    avp += generate_avp(266, 40, "00000000")                                                    #Vendor-Id
    avp += generate_avp(269, 40, string_to_hex("PyHSS"))                                        #Product-Name
    avp += generate_avp(267, 40, "000027d9")                                                    #Firmware-Revision
    avp += generate_avp(260, 40, "000001024000000c010000160000010a4000000c000028af")            #Vendor-Specific-Application-ID
    avp += generate_avp(258, 40, "ffffffff")                                                    #Auth-Application-ID
    avp += generate_avp(265, 40, "0000159f")                                                    #Supported-Vendor-ID (3GGP v2)
    avp += generate_avp(265, 40, "000028af")                                                    #Supported-Vendor-ID (3GPP)
    avp += generate_avp(265, 40, "000032db")                                                    #Supported-Vendor-ID (ETSI)
    response = generate_diameter_packet("01", "00", 257, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
    return response


def Answer_280(packet_vars, avps):                                                      #Device Watchdog Answer
    avp = ''                                                                                    #Initiate empty var AVP 
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))            #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(278, 40, AVP_278_Origin_State_Incriment(avps))                          #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
    response = generate_diameter_packet("01", "00", 280, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
    return response


#Disconnect Peer Answer    
def Answer_282(packet_vars, avps):                                                      
    avp = ''                                                                                    #Initiate empty var AVP 
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))            #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    response = generate_diameter_packet("01", "00", 282, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
    return response


#3GPP S6a/S6d Update Location Answer
def Answer_16777251_316(packet_vars, avps):
    avp = ''                                                                                    #Initiate empty var AVP
    session_id = get_avp_data(avps, 263)[0]                                                     #Get Session-ID
    avp += generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))          #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    avp += generate_avp(277, 40, "00000001")                                                    #Auth-Session-State    
    avp += generate_vendor_avp(1406, "c0", 10415, "00000001")                                   #ULA Flags
                                                                                                #Subscription-Data
    avp += generate_vendor_avp(1619, "80", 10415, "000002d0")                                   #Subscribed-Periodic-RAU-TAU-Timer (value 720)
    avp += generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID    
                                                                                                #Supported-Features
    avp += generate_vendor_avp(628, "80", 10415, "0000010a4000000c000028af000001024000000c01000023")
    print("Final AVP set: " + str(avp))
    response = generate_diameter_packet("01", "40", 316, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
    print("Final Response: " + str(response))
    return response



#3GPP S6a/S6d Authentication Information Answer  (ToDo - Generate Vectors dynamically)
def Answer_16777251_318(packet_vars, avps):                                              
    avp = ''                                                                                    #Initiate empty var AVP
    session_id = get_avp_data(avps, 263)[0]                                                     #Get Session-ID
    avp += generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
                                                                                                #Authentication-Info (10415 / 3GPP)
    vectors_file = open("vectors.txt", "r")                                                     #Load pregenerated authentication vectors from file
    for lines in vectors_file:
        print("Line: " )
        print(lines)
    vectors_file.close()
    avp += generate_vendor_avp(1413, "c0", 10415, lines)  
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))          #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    avp += generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
    avp += generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
    
    response = generate_diameter_packet("01", "00", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
    return response


#3GPP Gx Credit Control Answer
def Answer_16777238_272(packet_vars, avps):
    CC-Request-Type = get_avp_data(avps, 416)[0]
    print("CC Request Type is: " + str(CC-Request-Type))
    avp = ''                                                                                    #Initiate empty var AVP
    session_id = get_avp_data(avps, 263)[0]                                                     #Get Session-ID
    avp += generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
    avp += generate_avp(258, 40, "01000016")                                                    #Auth-Application-Id (3GPP Gx 16777238)
    avp += generate_avp(416, 40, str(binascii.hexlify(str.encode(str(CC-Request-Type))),'ascii'))                                                    #CC-Request-Type (ToDo - Check dyanmically generating)
    avp += generate_avp(415, 40, "00000000")                                                    #CC-Request-Number (ToDo - Match request CC-Request-Number)
    if int(CC-Request-Type) == 1:
                                                                                                    #Default-EPS-Bearer-QoS(1049) (Sets ARP & QCI. ToDo - Check Spec as to correct value encoding)
        avp += generate_vendor_avp(1049, "80", 10415, "00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af00000001")
                                                                                                    #Supported-Features(628) (Gx feature list)
        avp += generate_vendor_avp(628, "80", 10415, "0000027580000010000028af000000010000027680000010000028af0000000b")
    avp += generate_avp(264, 40, str(binascii.hexlify(b'pcrf.localdomain'),'ascii'))            #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    response = generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
    return response



#### Diameter Requests ####

def Request_282():                                                                      #Disconnect Peer Request
    avp = ''                                                                                    #Initiate empty var AVP 
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))            #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(273, 40, "00000000")                                                    #Disconnect-Cause (REBOOTING (0))
    response = generate_diameter_packet("01", "80", 282, 0, generate_id(4), generate_id(4), avp)                                                            #Generate Diameter packet
    return response



def Request_16777251_318():                                                             #3GPP S6a/S6d Authentication Information Request (ToDo - Test)
    avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
    sessionid = 'nickpc.localdomain;' + generate_id(5) + ';1;app_s6a'              #Session state generate
    avp += generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
    avp += generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))            #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))             #Destination Host
    avp += generate_avp(1, 40, str(binascii.hexlify(b'505931111111116'),'ascii'))               #Username (IMSI)
    avp += generate_vendor_avp(1408, "c0", 10415, "00000582c0000010000028af0000000100000584c0000010000028af00000001")
    avp += generate_vendor_avp(1407, "c0", 10415, "05f539")                                     #Visited-PLMN-Id(1407) (value MCC:1 MNC: 01)    
    avp += generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
       
    #avp += generate_avp(293, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm                                                                                              #Requested-EUTRAN-Authentication-Info(1408)
    
    
    response = generate_diameter_packet("01", "c0", 318, 16777251, generate_id(4), generate_id(4), avp)     #Generate Diameter packet
    return response



