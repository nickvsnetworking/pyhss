#Diameter Packet Decoder / Encoder & Tools

import socket
import sys
import binascii
import math
import uuid
import os
sys.path.append(os.path.realpath('lib'))
import S6a_crypt

#Generates rounding for calculating padding
def myround(n, base=4):
    if(n > 0):
        return math.ceil(n/4.0) * 4;
    elif( n < 0):
        return math.floor(n/4.0) * 4;
    else:
        return 4;

#Converts a dotted-decimal IPv4 address to hex
def ip_to_hex(ip):
    ip = ip.split('.')
    ip_hex = "0001"         #Only works for IPv4
    ip_hex = ip_hex + str(format(int(ip[0]), 'x').zfill(2))
    ip_hex = ip_hex + str(format(int(ip[1]), 'x').zfill(2))
    ip_hex = ip_hex + str(format(int(ip[2]), 'x').zfill(2))
    ip_hex = ip_hex + str(format(int(ip[3]), 'x').zfill(2))
    return ip_hex


#Converts string to hex
def string_to_hex(string):
    string_bytes = string.encode('utf-8')
    return str(binascii.hexlify(string_bytes), 'ascii')

#Generates a valid random ID to use
def generate_id(length):
    length = length * 2
    return str(uuid.uuid4().hex[:length])



#Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
#AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
def generate_avp(avp_code, avp_flags, avp_content):
    avp_code = format(avp_code,"x").zfill(8)
    
    avp_length = 1 ##This is a placeholder that's overwritten later

    #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
    avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_content)
    avp_length = int(len(avp)/2)

    if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
        avp_padding = ''
    else:                       #Not multiple of 4 - Padding needed
        rounded_value = myround(avp_length)
        avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)

    avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_content) + str(avp_padding)

    return avp

#Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
#AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
def generate_vendor_avp(avp_code, avp_flags, avp_vendorid, avp_content):
    avp_code = format(avp_code,"x").zfill(8)
    
    avp_length = 1 ##This is a placeholder that gets overwritten later

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
   
    packet_command_code = format(packet_command_code,"x").zfill(6)
    
    packet_application_id = format(packet_application_id,"x").zfill(8)
    
    packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
    packet_length = int(round(len(packet_hex))/2)
    packet_length = format(packet_length,"x").zfill(6)
    
    packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
    return packet_hex




def decode_diameter_packet(data):
    packet_vars = {}
    avps = []
    data = data.hex()

    packet_vars['packet_version'] = data[0:2]
    packet_vars['length'] = int(data[2:8], 16)
    packet_vars['flags'] = data[8:10]       
    packet_vars['command_code'] = int(data[10:16], 16)
    packet_vars['ApplicationId'] = int(data[16:24], 16)
    packet_vars['hop-by-hop-identifier'] = data[24:32]
    packet_vars['end-to-end-identifier'] = data[32:40]

    avp_sum = data[40:]

    avp_vars, remaining_avps = decode_avp_packet(avp_sum)
    avps.append(avp_vars)
    
    while len(remaining_avps) > 0:
        avp_vars, remaining_avps = decode_avp_packet(remaining_avps)
        avps.append(avp_vars)
    else:
        pass

    return packet_vars, avps

def decode_avp_packet(data):                       
    avp_vars = {}

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
        #Multiple of 4 - No Padding needed
        avp_vars['padding'] = 0
    else:
        #Not multiple of 4 - Padding needed
        rounded_value = myround(avp_vars['avp_length'])
        avp_vars['padding'] = int( rounded_value - avp_vars['avp_length']) * 2
    avp_vars['padded_data'] = data[(avp_vars['avp_length']*2):(avp_vars['avp_length']*2)+avp_vars['padding']]

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

#Loads a subscriber's information from CSV file into dict for referencing
def GetSubscriberInfo(imsi):
    subscriber_details = {}
    print("Looking up " + str(imsi))
    subs_file = open("subscribers.csv", "r")
    for subscribers in subs_file:
        subscribers = subscribers.split(",")
        #Find specific IMSI config
        if str(subscribers[0]) == str(imsi):
            print("Found match for " + str(imsi))
            subscriber_details['K'] = subscribers[1].rstrip()
            if len(subscriber_details['K']) != 32:
                print("Invalid K Length")
                return
            subscriber_details['OP'] = subscribers[2].rstrip()
            if len(subscriber_details['OP']) != 32:
                print("Invalid OP Length")
                return
            subscriber_details['AMF'] = subscribers[3].rstrip()
            subscriber_details['SQN'] = subscribers[4].rstrip()
    subs_file.close()
    return subscriber_details


#### Diameter Answers ####


#Capabilities Exchange Answer
def Answer_257(packet_vars, avps):
    avp = ''                                                                                    #Initiate empty var AVP 
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))          #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
        if avps_to_check['avp_code'] == 278:                                
            avp += generate_avp(278, 40, AVP_278_Origin_State_Incriment(avps))                  #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
    avp += generate_avp(257, 40, ip_to_hex(socket.gethostbyname(socket.gethostname())))         #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
    avp += generate_avp(266, 40, "00000000")                                                    #Vendor-Id
    avp += generate_avp(269, 40, string_to_hex("PyHSS"))                                        #Product-Name
    avp += generate_avp(267, 40, "000027d9")                                                    #Firmware-Revision
    avp += generate_avp(260, 40, "000001024000000c01000023" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
    avp += generate_avp(260, 40, "000001024000000c01000016" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx) 
    avp += generate_avp(258, 40, "ffffffff")                                                    #Auth-Application-ID
    avp += generate_avp(265, 40, "0000159f")                                                    #Supported-Vendor-ID (3GGP v2)
    avp += generate_avp(265, 40, "000028af")                                                    #Supported-Vendor-ID (3GPP)
    avp += generate_avp(265, 40, "000032db")                                                    #Supported-Vendor-ID (ETSI)
    response = generate_diameter_packet("01", "00", 257, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
    print("Debug Response:" )
    print(response)
    print("\n")
    
    return response



#Device Watchdog Answer
def Answer_280(packet_vars, avps):                                                      
    avp = ''                                                                                    #Initiate empty var AVP 
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))          #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
        if avps_to_check['avp_code'] == 278:                                
            avp += generate_avp(278, 40, AVP_278_Origin_State_Incriment(avps))                  #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
    response = generate_diameter_packet("01", "00", 280, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
    return response


#Disconnect Peer Answer    
def Answer_282(packet_vars, avps):                                                      
    avp = ''                                                                                    #Initiate empty var AVP 
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))          #Origin Host
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
    avp += generate_vendor_avp(1400, "c0", 10415, "00000592c0000010000028af0000002000000590c0000010000028af0000000000000589c0000010000028af000000020000059bc000002c000028af00000204c0000010000028af3e80000000000203c0000010000028af3e80000000000595c0000158000028af0000058fc0000010000028af0000000100000594c0000010000028af0000000000000596c0000094000028af0000058fc0000010000028af00000001000005b0c0000010000028af00000002000001ed40000010696e7465726e657400000597c0000058000028af00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af0000000100000596c0000098000028af0000058fc0000010000028af00000002000005b0c0000010000028af00000002000001ed4000001374656c737472612e7761700000000597c0000058000028af00000404c0000010000028af000000050000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af00000001")                                   #Subscription-Data
    avp += generate_vendor_avp(1619, "80", 10415, "000002d0")                                   #Subscribed-Periodic-RAU-TAU-Timer (value 720)
    avp += generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID    
                                                                                                #Supported-Features
    avp += generate_vendor_avp(628, "80", 10415, "0000010a4000000c000028af000001024000000c01000023")
    print("Final AVP set: " + str(avp))
    response = generate_diameter_packet("01", "40", 316, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
    print("Final Response: " + str(response))
    return response



#3GPP S6a/S6d Authentication Information Answer
def Answer_16777251_318(packet_vars, avps):
    imsi = get_avp_data(avps, 1)[0]                                                             #Get IMSI from User-Name AVP in request
    imsi = binascii.unhexlify(imsi).decode('utf-8')                                             #Covert IMSI
    plmn = get_avp_data(avps, 1407)[0]                                                          #Get PLMN from User-Name AVP in request

    subscriber_details = GetSubscriberInfo(imsi)                                                #Get subscriber details
    key = subscriber_details['K']                                                               #Format keys
    op = subscriber_details['OP']                                                               #Format keys
    amf = subscriber_details['AMF']                                                             #Format keys
    sqn = subscriber_details['SQN']                                                             #Format keys
    rand, xres, autn, kasme = S6a_crypt.generate_eutran_vector(key, op, amf, sqn)               #Generate Authentication Vectors

    eutranvector = ''                                                                           #This goes into the payload of AVP 10415 (Authentication info)
    eutranvector += generate_vendor_avp(1447, "c0", 10415, rand)                                #And is made up of other AVPs joined together with RAND
    eutranvector += generate_vendor_avp(1448, "c0", 10415, xres)                                #XRes
    eutranvector += generate_vendor_avp(1449, "c0", 10415, autn)                                #AUTN
    eutranvector += generate_vendor_avp(1450, "c0", 10415, kasme)                               #And KASME

    eutranvector = generate_vendor_avp(1414, "c0", 10415, eutranvector)                         #Put EUTRAN vectors in E-UTRAN-Vector AVP
    
    avp = ''                                                                                    #Initiate empty var AVP
    session_id = get_avp_data(avps, 263)[0]                                                     #Get Session-
    avp += generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
    avp += generate_vendor_avp(1413, "c0", 10415, eutranvector)                                 #Authentication-Info (3GPP)                                      
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))          #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    avp += generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
    avp += generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
    
    response = generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
    return response



#3GPP Gx Credit Control Answer
def Answer_16777238_272(packet_vars, avps):
    CC_Request_Type = get_avp_data(avps, 416)[0]
    print("CC Request Type is: " + str(CC_Request_Type))
    CC_Request_Number = get_avp_data(avps, 415)[0]
    print("CC Request Number is: " + str(CC_Request_Number))
    OriginHost = get_avp_data(avps, 264)[0]
    print("OriginHost: " + str(OriginHost) + " type " + str(type(OriginHost)))
    avp = ''                                                                                    #Initiate empty var AVP
    session_id = get_avp_data(avps, 263)[0]                                                     #Get Session-ID
    avp += generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
    avp += generate_avp(258, 40, "01000016")                                                    #Auth-Application-Id (3GPP Gx 16777238)
    avp += generate_avp(416, 40, format(int(CC_Request_Type),"x").zfill(8))                     #CC-Request-Type (ToDo - Check dyanmically generating)
    avp += generate_avp(415, 40, format(int(CC_Request_Number),"x").zfill(8))                   #CC-Request-Number (ToDo - Check dyanmically generating)
    if int(CC_Request_Type) == 1:
                                                                                                #Default-EPS-Bearer-QoS(1049) (Sets ARP & QCI. ToDo - Check Spec as to correct value encoding)
        avp += generate_vendor_avp(1049, "80", 10415, "00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af00000001")
                                                                                                #Supported-Features(628) (Gx feature list)
        avp += generate_vendor_avp(628, "80", 10415, "0000027580000010000028af000000010000027680000010000028af0000000b")
    avp += generate_avp(264, 40, str(binascii.hexlify(str.encode(str(OriginHost))),'ascii'))    #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
    response = generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
    return response


#3GPP Cx Multimedia Authentication Answer
def Answer_16777216_303(packet_vars, avps):
    avp = ''                                                                                    #Initiate empty var AVP
    session_id = get_avp_data(avps, 263)[0]                                                     #Get Session-ID
    avp += generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
    avp += generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID
    avp += generate_avp(277, 40, "00000001")                                                    #Auth Session State
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))          #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Host
    avp += generate_avp(293, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
    avp += generate_avp(1, 40, str(binascii.hexlify(b'001011234567081@ims.mnc001.mcc001.3gppnetwork.org'),'ascii'))               #Username
    avp += generate_vendor_avp(601, "c0", 10415, str(binascii.hexlify(b'001011234567081'),'ascii'))#Public Identity
    avp += generate_vendor_avp(612, "c0", 10415, "00000260c000001c000028af4469676573742d414b4176312d4d4435")    #3GPP-SIP-Auth-Data-Item
    avp += generate_vendor_avp(607, "c0", 10415, "00000001")                                    #3GPP-SIP-Number-Auth-Items
    avp += generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(b'PyHSS'),'ascii'))       #Server Name
    response = generate_diameter_packet("01", "c0", 303, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
    return response
    
    
#### Diameter Requests ####

#Disconnect Peer Request
def Request_282():                                                                      
    avp = ''                                                                                    #Initiate empty var AVP 
    avp += generate_avp(264, 40, str(binascii.hexlify(b'nickpc.localdomain'),'ascii'))          #Origin Host
    avp += generate_avp(296, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Origin Realm
    avp += generate_avp(273, 40, "00000000")                                                    #Disconnect-Cause (REBOOTING (0))
    response = generate_diameter_packet("01", "80", 282, 0, generate_id(4), generate_id(4), avp)#Generate Diameter packet
    return response


#3GPP S6a/S6d Authentication Information Request
def Request_16777251_318():                                                             
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



