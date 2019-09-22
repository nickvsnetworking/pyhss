#Diameter Packet Decoder / Encoder & Tools
import socket
import sys
import binascii
import math
import uuid
import os
sys.path.append(os.path.realpath('lib'))
import S6a_crypt

class Diameter:


    ##Function Definitions

    #Generates rounding for calculating padding
    def myround(self, n, base=4):
        if(n > 0):
            return math.ceil(n/4.0) * 4;
        elif( n < 0):
            return math.floor(n/4.0) * 4;
        else:
            return 4;

    #Converts a dotted-decimal IPv4 address to hex
    def ip_to_hex(self, ip):
        ip = ip.split('.')
        ip_hex = "0001"         #Only works for IPv4
        ip_hex = ip_hex + str(format(int(ip[0]), 'x').zfill(2))
        ip_hex = ip_hex + str(format(int(ip[1]), 'x').zfill(2))
        ip_hex = ip_hex + str(format(int(ip[2]), 'x').zfill(2))
        ip_hex = ip_hex + str(format(int(ip[3]), 'x').zfill(2))
        return ip_hex

    #Converts string to hex
    def string_to_hex(self, string):
        string_bytes = string.encode('utf-8')
        return str(binascii.hexlify(string_bytes), 'ascii')

    #Converts int to hex padded to required number of bytes
    def int_to_hex(self, input_int, output_bytes):
        
        return format(input_int,"x").zfill(output_bytes*2)

    #Generates a valid random ID to use
    def generate_id(self, length):
        length = length * 2
        return str(uuid.uuid4().hex[:length])

    #Generates a random unsigned 32-bit integer field (in network byte order) for use in Hop-by-Hop Identifiers and End-to-End Identifiers
    def generate32bitint(self):
        return generate_id(4)


    #Hexify the vars we got when initializing the class
    def __init__(self, OriginHost, OriginRealm, ProductName):
        self.OriginHost = self.string_to_hex(OriginHost)
        self.OriginRealm = self.string_to_hex(OriginRealm)
        self.ProductName = self.string_to_hex(ProductName)


    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
    def generate_avp(self, avp_code, avp_flags, avp_content):
        avp_code = format(avp_code,"x").zfill(8)
        
        avp_length = 1 ##This is a placeholder that's overwritten later

        #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
        avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_content)
        avp_length = int(len(avp)/2)

        if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
            avp_padding = ''
        else:                       #Not multiple of 4 - Padding needed
            rounded_value = self.myround(avp_length)
            avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)

        avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_content) + str(avp_padding)

        return avp

    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
    def generate_vendor_avp(self, avp_code, avp_flags, avp_vendorid, avp_content):
        avp_code = format(avp_code,"x").zfill(8)
        
        avp_length = 1 ##This is a placeholder that gets overwritten later

        avp_vendorid = format(int(avp_vendorid),"x").zfill(8)
        
        #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
        avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_vendorid) + str(avp_content)
        avp_length = int(len(avp)/2)

        if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
            avp_padding = ''
        else:                       #Not multiple of 4 - Padding needed
            rounded_value = self.myround(avp_length)
            #print("Rounded value is " + str(rounded_value))
            #print("Has " + str( int( rounded_value - avp_length)) + " bytes of padding")
            avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)


        
        avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_vendorid) + str(avp_content) + str(avp_padding)

        return avp




    def generate_diameter_packet(self, packet_version, packet_flags, packet_command_code, packet_application_id, packet_hop_by_hop_id, packet_end_to_end_id, avp):
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




    def decode_diameter_packet(self, data):
        packet_vars = {}
        avps = []
        
        if type(data) is bytes:
            data = data.hex()


        packet_vars['packet_version'] = data[0:2]
        packet_vars['length'] = int(data[2:8], 16)
        packet_vars['flags'] = data[8:10]       
        packet_vars['command_code'] = int(data[10:16], 16)
        packet_vars['ApplicationId'] = int(data[16:24], 16)
        packet_vars['hop-by-hop-identifier'] = data[24:32]
        packet_vars['end-to-end-identifier'] = data[32:40]

        avp_sum = data[40:]

        avp_vars, remaining_avps = self.decode_avp_packet(avp_sum)
        avps.append(avp_vars)
        
        while len(remaining_avps) > 0:
            avp_vars, remaining_avps = self.decode_avp_packet(remaining_avps)
            avps.append(avp_vars)
        else:
            pass

        return packet_vars, avps

    def decode_avp_packet(self, data):                       
        avp_vars = {}
        avp_vars['avp_code'] = int(data[0:8], 16)
        
        avp_vars['avp_flags'] = data[8:10]
        avp_vars['avp_length'] = int(data[10:16], 16)
        if avp_vars['avp_flags'] == "c0":
            #If c0 is present AVP is Vendor AVP
            avp_vars['vendor_id'] = int(data[16:24], 16)
            avp_vars['misc_data'] = data[24:(avp_vars['avp_length']*2)]
        else:
            #if is not a vendor AVP
            avp_vars['misc_data'] = data[16:(avp_vars['avp_length']*2)]
        if avp_vars['avp_length'] % 4  == 0:
            #Multiple of 4 - No Padding needed
            avp_vars['padding'] = 0
        else:
            #Not multiple of 4 - Padding needed
            rounded_value = self.myround(avp_vars['avp_length'])
            avp_vars['padding'] = int( rounded_value - avp_vars['avp_length']) * 2
        avp_vars['padded_data'] = data[(avp_vars['avp_length']*2):(avp_vars['avp_length']*2)+avp_vars['padding']]


        #If body of avp_vars['misc_data'] contains AVPs, then decode each of them as a list of dicts like avp_vars['misc_data'] = [avp_vars, avp_vars]
        try:
              sub_avp_vars, sub_remaining_avps = self.decode_avp_packet(avp_vars['misc_data'])
              #Sanity check - If the avp code is greater than 9999 it's probably not an AVP after all...
              if int(sub_avp_vars['avp_code']) > 9999:
                  pass
              else:
                  #If the decoded AVP is valid store it
                  avp_vars['misc_data'] = []
                  avp_vars['misc_data'].append(sub_avp_vars)
                  #While there are more AVPs to be decoded, decode them:
                  while len(sub_remaining_avps) > 0:
                      sub_avp_vars, sub_remaining_avps = self.decode_avp_packet(sub_remaining_avps)
                      avp_vars['misc_data'].append(sub_avp_vars)
              
        except Exception as e:
            #print("failed to decode sub-avp - error: " + str(e))
            pass


        remaining_avps = data[(avp_vars['avp_length']*2)+avp_vars['padding']:]  #returns remaining data in avp string back for processing again

        return avp_vars, remaining_avps


    def get_avp_data(self, avps, avp_code):               #Loops through list of dicts generated by the packet decoder, and returns the data for a specific AVP code in list (May be more than one AVP with same code but different data)
        misc_data = []
        for keys in avps:
            if keys['avp_code'] == avp_code:
                misc_data.append(keys['misc_data'])
        return misc_data


    def decode_diameter_packet_length(self, data):
        packet_vars = {}
        avps = []
        data = data.hex()

        packet_vars['packet_version'] = data[0:2]
        packet_vars['length'] = int(data[2:8], 16)
        if packet_vars['packet_version'] == "01":
            return packet_vars['length']
        else:
            return False


    def AVP_278_Origin_State_Incriment(self, avps):                                               #Capabilities Exchange Answer incriment AVP body
        for avp_dicts in avps:
            if avp_dicts['avp_code'] == 278:
                origin_state_incriment_int = int(avp_dicts['misc_data'], 16)
                origin_state_incriment_int = origin_state_incriment_int + 1
                origin_state_incriment_hex = format(origin_state_incriment_int,"x").zfill(8)
                return origin_state_incriment_hex


    #Loads a subscriber's information from CSV file into dict for referencing
    def GetSubscriberInfo(self, imsi):
        subscriber_details = {}
        #print("Looking up " + str(imsi))
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
                return subscriber_details
        subs_file.close()
        raise ValueError("Subscriber not present in CSV")

    #Loads a subscriber's information from CSV file into dict for referencing
    def UpdateSubscriberSQN(self, imsi, sqn):
        subscriber_details = {}
        #print("Looking up " + str(imsi))
        subs_file = open("subscribers.csv", "r")
        writeback_file = open("writeback.csv", "w")
        for subscribers in subs_file:
            subscribers = subscribers.split(",")
            #Find specific IMSI config
            if str(subscribers[0]) == str(imsi):
                print("Found match for " + str(imsi))
                subscriber_details['K'] = subscribers[1].rstrip()
                subscribers[4] = str(sqn)

            writeback_file.write(subscribers[0] + "," + subscribers[1] + ","  + subscribers[2] + ","  + subscribers[3] + ","  + subscribers[4].rstrip() + "\n")

        subs_file.close()
        writeback_file.close()
        os.remove("subscribers.csv")
        os.rename("writeback.csv", "subscribers.csv")
        return(sqn)







    #### Diameter Answers ####


    #Capabilities Exchange Answer
    def Answer_257(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCESS (2001))
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
            if avps_to_check['avp_code'] == 278:                                
                avp += self.generate_avp(278, 40, self.AVP_278_Origin_State_Incriment(avps))                  #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
        avp += self.generate_avp(257, 40, self.ip_to_hex(socket.gethostbyname(socket.gethostname())))         #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
        avp += self.generate_avp(266, 40, "00000000")                                                    #Vendor-Id
        avp += self.generate_avp(269, 40, self.ProductName)                                                   #Product-Name
        avp += self.generate_avp(267, 40, "000027d9")                                                    #Firmware-Revision
        avp += self.generate_avp(260, 40, "000001024000000c01000023" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        avp += self.generate_avp(260, 40, "000001024000000c01000016" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        avp += self.generate_avp(258, 40, format(int(4294967295),"x").zfill(8))                          #Auth-Application-ID Relay
        avp += self.generate_avp(265, 40, format(int(5535),"x").zfill(8))                               #Supported-Vendor-ID (3GGP v2)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(265, 40, format(int(13019),"x").zfill(8))                               #Supported-Vendor-ID 13019 (ETSI)
        response = self.generate_diameter_packet("01", "00", 257, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet       
        return response



    #Device Watchdog Answer
    def Answer_280(self, packet_vars, avps):                                                      
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCESS (2001))
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
            if avps_to_check['avp_code'] == 278:                                
                avp += self.generate_avp(278, 40, self.AVP_278_Origin_State_Incriment(avps))                  #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
        response = self.generate_diameter_packet("01", "00", 280, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
        return response


    #Disconnect Peer Answer    
    def Answer_282(self, packet_vars, avps):                                                      
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCESS (2001))
        response = self.generate_diameter_packet("01", "00", 282, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
        return response


    #3GPP S6a/S6d Update Location Answer
    def Answer_16777251_316(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCESS (2001))
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State    
        avp += self.generate_vendor_avp(1406, "c0", 10415, "00000001")                                   #ULA Flags

        #Subscription Data:
        subscription_data = ''
        subscription_data += self.generate_vendor_avp(1426, "c0", 10415, "00000020")                     #Access Restriction Data
        subscription_data += self.generate_vendor_avp(1424, "c0", 10415, "00000000")                     #Subscriber-Status (SERVICE_GRANTED)
        subscription_data += self.generate_vendor_avp(1417, "c0", 10415, "00000002")                     #Network-Access-Mode (ONLY_PACKET)

        #AMBR is a sub-AVP of Subscription Data
        AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
        AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(1048576000, 4))                    #Max-Requested-Bandwidth-UL / DL
        AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(1048576000, 4))                    #Max-Requested-Bandwidth-UL / DL
        subscription_data += self.generate_vendor_avp(1435, "c0", 10415, AMBR)                           #Add AMBR AVP in two sub-AVPs

        #APN Configuration Profile is a sub AVP of Subscription Data
        APN_Configuration_Profile = ''
        APN_Configuration_Profile += self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(1, 4))     #Context Identifier
        APN_Configuration_Profile += self.generate_vendor_avp(1428, "c0", 10415, self.int_to_hex(0, 4))     #All-APN-Configurations-Included-Indicator

        #Sub AVPs of APN Configuration Profile
        AVP_context_identifer = self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(1, 4))
        AVP_PDN_type = self.generate_vendor_avp(1456, "c0", 10415, self.int_to_hex(2, 4))
        AVP_Service_Selection = self.generate_avp(493, "40",  self.string_to_hex('telstra.wap'))
        
        AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(9, 4))

        AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(8, 4))
        AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(1, 4))
        AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "c0", 10415, self.int_to_hex(1, 4))
        AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
        AVP_EPS_Subscribed_QoS_Profile = self.generate_vendor_avp(1431, "c0", 10415, AVP_QoS + AVP_ARP)
        #first APN
        APN_Configuration = self.generate_vendor_avp(1430, "c0", 10415, AVP_context_identifer + AVP_PDN_type + AVP_Service_Selection + AVP_EPS_Subscribed_QoS_Profile)
        #second APN
        AVP_Service_Selection = self.generate_avp(493, "40",  self.string_to_hex('internet'))
        APN_Configuration += self.generate_vendor_avp(1430, "c0", 10415, AVP_context_identifer + AVP_PDN_type + AVP_Service_Selection + AVP_EPS_Subscribed_QoS_Profile)
        
        subscription_data += self.generate_vendor_avp(1619, "80", 10415, "000002d0")                                   #Subscribed-Periodic-RAU-TAU-Timer (value 720)
        subscription_data += self.generate_vendor_avp(1429, "c0", 10415, AVP_context_identifer + self.generate_vendor_avp(1428, "c0", 10415, self.int_to_hex(0, 4)) + APN_Configuration)
        
        avp += self.generate_vendor_avp(1400, "c0", 10415, subscription_data)                            #Subscription-Data

        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID    
                                                                                                    #Supported-Features
        avp += self.generate_vendor_avp(628, "80", 10415, "0000010a4000000c000028af000001024000000c01000023")
        
        response = self.generate_diameter_packet("01", "40", 316, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        
  
        return response



    #3GPP S6a/S6d Authentication Information Answer
    def Answer_16777251_318(self, packet_vars, avps):
        print(self.get_avp_data(avps, 1))
        imsi = self.get_avp_data(avps, 1)[0]                                                             #Get IMSI from User-Name AVP in request
        imsi = binascii.unhexlify(imsi).decode('utf-8')                                             #Covert IMSI
        plmn = self.get_avp_data(avps, 1407)[0]                                                          #Get PLMN from User-Name AVP in request

        try:
            subscriber_details = self.GetSubscriberInfo(imsi)                                                #Get subscriber details
            self.UpdateSubscriberSQN(imsi, int(subscriber_details['SQN']) + 1)
        except:
            #Handle if the subscriber is not present in HSS return "DIAMETER_ERROR_USER_UNKNOWN"
            print("Subscriber unknown")
            avp = ''
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
            avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

            #Experimental Result AVP(Response Code for Failure)
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(5001, 4))                 #AVP Experimental-Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001)
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            
            avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
            avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
            response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

        
        for avp in avps:
            if avp['avp_code'] == 1408:
                print("AVP: Requested-EUTRAN-Authentication-Info(1408) l=44 f=VM- vnd=TGPP")
                EUTRAN_Authentication_Info = avp['misc_data']
                for sub_avp in EUTRAN_Authentication_Info:
                    print(sub_avp)
                    #If resync request
                    if sub_avp['avp_code'] == 1411:
                        print("AVP: Re-Synchronization-Info(1411): ")
                        print(sub_avp['misc_data'])
    
        
        key = subscriber_details['K']                                                               #Format keys
        op = subscriber_details['OP']                                                               #Format keys
        amf = subscriber_details['AMF']                                                             #Format keys
        sqn = subscriber_details['SQN']                                                             #Format keys
        plmn = self.get_avp_data(avps, 1407)[0]                                                     #Get PLMN from request
        rand, xres, autn, kasme = S6a_crypt.generate_eutran_vector(key, op, amf, sqn, plmn) 

        eutranvector = ''                                                                           #This goes into the payload of AVP 10415 (Authentication info)
        eutranvector += self.generate_vendor_avp(1447, "c0", 10415, rand)                                #And is made up of other AVPs joined together with RAND
        eutranvector += self.generate_vendor_avp(1448, "c0", 10415, xres)                                #XRes
        eutranvector += self.generate_vendor_avp(1449, "c0", 10415, autn)                                #AUTN
        eutranvector += self.generate_vendor_avp(1450, "c0", 10415, kasme)                               #And KASME

        eutranvector = self.generate_vendor_avp(1414, "c0", 10415, eutranvector)                         #Put EUTRAN vectors in E-UTRAN-Vector AVP
        
        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_vendor_avp(1413, "c0", 10415, eutranvector)                                 #Authentication-Info (3GPP)                                      
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCESS (2001))
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
        
        response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response




    #3GPP Gx Credit Control Answer
    def Answer_16777238_272(self, packet_vars, avps):
        CC_Request_Type = self.get_avp_data(avps, 416)[0]
        CC_Request_Number = self.get_avp_data(avps, 415)[0]
        self.OriginHost = self.get_avp_data(avps, 264)[0]
        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(258, 40, "01000016")                                                    #Auth-Application-Id (3GPP Gx 16777238)
        avp += self.generate_avp(416, 40, format(int(CC_Request_Type),"x").zfill(8))                     #CC-Request-Type (ToDo - Check dyanmically generating)
        avp += self.generate_avp(415, 40, format(int(CC_Request_Number),"x").zfill(8))                   #CC-Request-Number (ToDo - Check dyanmically generating)
        if int(CC_Request_Type) == 1:
                                                                                                    #Default-EPS-Bearer-QoS(1049) (Sets ARP & QCI. ToDo - Check Spec as to correct value encoding)
            avp += self.generate_vendor_avp(1049, "80", 10415, "00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af00000001")
                                                                                                    #Supported-Features(628) (Gx feature list)
            avp += self.generate_vendor_avp(628, "80", 10415, "0000027580000010000028af000000010000027680000010000028af0000000b")
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCESS (2001))
        response = self.generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response


    #3GPP Cx Multimedia Authentication Answer
    def Answer_16777216_303(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth Session State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCESS (2001))
        avp += self.generate_avp(1, 40, str(binascii.hexlify(b'001011234567081@ims.mnc001.mcc001.3gppnetwork.org'),'ascii'))               #Username
        avp += self.generate_vendor_avp(601, "c0", 10415, str(binascii.hexlify(b'001011234567081'),'ascii'))#Public Identity

        #diameter.3GPP-SIP-Auth-Data-Item (ToDo - Make all these values dynamic)
        ##AVP Code: 608 3GPP-SIP-Authentication-Scheme
        avp_SIP_Authentication_Scheme = self.generate_vendor_avp(608, "c0", 10415, str(binascii.hexlify(b'Digest-AKAv1-MD5'),'ascii'))
        ##AVP Code: 609 3GPP-SIP-Authenticate
        avp_SIP_Authenticate = self.generate_vendor_avp(609, "c0", 10415, '6b22b83997afe941c07afc0337006e50081206ce13a280008212824af50aa149')
        ##AVP Code: 610 3GPP-SIP-Authorization
        avp_SIP_Authorization = self.generate_vendor_avp(610, "c0", 10415, '3344da564b8f010f')
        ##AVP Code: 625 Confidentiality-Key
        avp_Confidentialility_Key = self.generate_vendor_avp(625, "c0", 10415, 'e363a749ce898e2d76dc7767388d6c84')
        ##AVP Code: 626 Integrity-Key
        avp_Integrity_Key = self.generate_vendor_avp(626, "c0", 10415, '2f1ebab3d3b2bfb052784f5fb3db7299')
        auth_data_item = avp_SIP_Authentication_Scheme + avp_SIP_Authenticate + avp_SIP_Authorization + avp_Confidentialility_Key + avp_Integrity_Key
        avp += self.generate_vendor_avp(612, "c0", 10415, auth_data_item)    #3GPP-SIP-Auth-Data-Item
        
        avp += self.generate_vendor_avp(607, "c0", 10415, "00000001")                                    #3GPP-SIP-Number-Auth-Items

        experimental_avp = ''                                                                       #New empty avp for storing avp 297 contents
        experimental_avp = experimental_avp + self.generate_vendor_avp(266, 40, 10415, '')               #3GPP Vendor ID
        experimental_avp = experimental_avp + self.generate_avp(298, 40, "000007d1")                     #Expiremental Result Code 298 val DIAMETER_FIRST_REGISTRATION
        avp += self.generate_avp(297, 40, experimental_avp)                                              #Expirmental-Result
        
        response = self.generate_diameter_packet("01", "40", 303, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response
        
        
    #### Diameter Requests ####

    #Capabilities Exchange Request
    def Request_257(self):
        avp = ''
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(257, 40, self.ip_to_hex(socket.gethostbyname(socket.gethostname())))         #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
        avp += self.generate_avp(266, 40, "00000000")                                                    #Vendor-Id
        avp += self.generate_avp(269, 40, self.ProductName)                                                   #Product-Name
        avp += self.generate_avp(267, 40, "000027d9")                                                    #Firmware-Revision
        avp += self.generate_avp(260, 40, "000001024000000c01000023" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        avp += self.generate_avp(260, 40, "000001024000000c01000016" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        avp += self.generate_avp(258, 40, format(int(4294967295),"x").zfill(8))                          #Auth-Application-ID Relay
        avp += self.generate_avp(265, 40, format(int(5535),"x").zfill(8))                               #Supported-Vendor-ID (3GGP v2)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(265, 40, format(int(13019),"x").zfill(8))                               #Supported-Vendor-ID 13019 (ETSI)
        response = self.generate_diameter_packet("01", "80", 257, 0, self.generate_id(4), self.generate_id(4), avp)            #Generate Diameter packet
        return response

    #Device Watchdog Request
    def Request_280(self):
        avp = ''
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        response = self.generate_diameter_packet("01", "80", 280, 0, self.generate_id(4), self.generate_id(4), avp)#Generate Diameter packet
        return response

        
    #Disconnect Peer Request
    def Request_282(self):                                                                      
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(273, 40, "00000000")                                                    #Disconnect-Cause (REBOOTING (0))
        response = self.generate_diameter_packet("01", "80", 282, 0, self.generate_id(4), self.generate_id(4), avp)#Generate Diameter packet
        return response


    #3GPP S6a/S6d Authentication Information Request
    def Request_16777251_318(self, imsi):                                                             
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = 'nickpc.localdomain;' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_vendor_avp(1408, "c0", 10415, "00000582c0000010000028af0000000100000584c0000010000028af00000001")
        avp += self.generate_vendor_avp(1407, "c0", 10415, "05f539")                                     #Visited-PLMN-Id(1407) (value MCC:1 MNC: 01)    
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID       
        
        
        response = self.generate_diameter_packet("01", "c0", 318, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d Update Location Request
    def Request_16777251_316(self, imsi):                                                             
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = 'nickpc.localdomain;' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_vendor_avp(1032, "80", 10415, self.int_to_hex(1004, 4))                    #RAT-Type val=EUTRAN (1004)
        avp += self.generate_vendor_avp(1405, "c0", 10415, "00000002")                                  #ULR-Flags val=2
        avp += self.generate_vendor_avp(1407, "c0", 10415, "05f539")                                  #Visited-PLMN-Id            ##FIXME
        avp += self.generate_vendor_avp(1615, "80", 10415, "00000000")                                  #E-SRVCC-Capability val=UE-SRVCC-NOT-SUPPORTED (0)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID

        response = self.generate_diameter_packet("01", "c0", 316, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response
