#Diameter Packet Decoder / Encoder & Tools
from multiprocessing.sharedctypes import Value
import socket
import logging
import sys
import binascii
import math
import uuid
import os
sys.path.append(os.path.realpath('lib'))
import S6a_crypt

import jinja2
import yaml
import time
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

#Setup Logging
import logtool
from logtool import *
logtool = logtool.LogTool()
logtool.setup_logger('DiameterLogger', yaml_config['logging']['logfiles']['diameter_logging_file'], level=yaml_config['logging']['level'])
DiameterLogger = logging.getLogger('DiameterLogger')

DiameterLogger.info("Initialised Diameter Logger, importing database")
import database
DiameterLogger.info("Imported database")

if yaml_config['redis']['enabled'] == True:
    DiameterLogger.debug("Redis support enabled")
    import redis


class Diameter:
    ##Function Definitions


    #Generates rounding for calculating padding
    def myround(self, n, base=4):
        if(n > 0):
            return math.ceil(n/4.0) * 4
        elif( n < 0):
            return math.floor(n/4.0) * 4
        else:
            return 4

    #Converts a dotted-decimal IPv4 address or IPV6 address to hex
    def ip_to_hex(self, ip):
        #Determine IPvX version:
        if "." in ip:
            ip = ip.split('.')
            ip_hex = "0001"         #IPv4
            ip_hex = ip_hex + str(format(int(ip[0]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[1]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[2]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[3]), 'x').zfill(2))
        else:
            ip_hex = "0002"         #IPv6
            for parts in ip.split(":"):
                if parts == '':
                    ip_hex += "00000000"    #If :: represent as full
                else:
                    ip_hex += str(parts).zfill(4)
        #DiameterLogger.debug("Converted IP to hex - Input: " + str(ip) + " output: " + str(ip_hex))
        return ip_hex
    #Converts a hex formatted IPv4 address or IPV6 address to dotted-decimal 
    def hex_to_ip(self, hex_ip):
        if len(hex_ip) == 8:
            octet_1 = int(str(hex_ip[0:2]), base=16)
            octet_2 = int(str(hex_ip[2:4]), base=16)
            octet_3 = int(str(hex_ip[4:6]), base=16)
            octet_4 = int(str(hex_ip[6:8]), base=16)
            return str(octet_1) + "." + str(octet_2) + "." + str(octet_3) + "." + str(octet_4)
        elif len(hex_ip) == 32:
            n=4
            ipv6_split = [hex_ip[idx:idx + n] for idx in range(0, len(hex_ip), n)]
            ipv6_str = ''
            for octect in ipv6_split:
                ipv6_str += str(octect).lstrip('0') + ":"
            #Strip last Colon
            ipv6_str = ipv6_str[:-1]
            return ipv6_str

    #Converts string to hex
    def string_to_hex(self, string):
        string_bytes = string.encode('utf-8')
        return str(binascii.hexlify(string_bytes), 'ascii')

    #Converts int to hex padded to required number of bytes
    def int_to_hex(self, input_int, output_bytes):
        
        return format(input_int,"x").zfill(output_bytes*2)

    #Converts Hex byte to Binary
    def hex_to_bin(self, input_hex):
        return bin(int(str(input_hex), 16))[2:].zfill(8)

    #Generates a valid random ID to use
    def generate_id(self, length):
        length = length * 2
        return str(uuid.uuid4().hex[:length])

    def Reverse(self, str):
        stringlength=len(str)
        slicedString=str[stringlength::-1]
        return (slicedString)

    def DecodePLMN(self, plmn):
        DiameterLogger.debug("Decoded PLMN: " + str(plmn))
        mcc = self.Reverse(plmn[0:2]) + self.Reverse(plmn[2:4]).replace('f', '')
        DiameterLogger.debug("Decoded MCC: " + mcc)

        mnc = self.Reverse(plmn[4:6])
        DiameterLogger.debug("Decoded MNC: " + mnc)
        return mcc, mnc

    def EncodePLMN(self, mcc, mnc):
        plmn = list('XXXXXX')
        plmn[0] = self.Reverse(mcc)[1]
        plmn[1] = self.Reverse(mcc)[2]
        plmn[2] = "f"
        plmn[3] = self.Reverse(mcc)[0]
        plmn[4] = self.Reverse(mnc)[0]
        plmn[5] = self.Reverse(mnc)[1]
        plmn_list = plmn
        plmn = ''
        for bits in plmn_list:
            plmn = plmn + bits
        DiameterLogger.debug("Encoded PLMN: " + str(plmn))
        return plmn

    def TBCD_special_chars(self, input):
        DiameterLogger.debug("Special character possible in " + str(input))
        if input == "*":
            DiameterLogger.debug("Found * - Returning 1010")
            return "1010"
        elif input == "#":
            DiameterLogger.debug("Found # - Returning 1011")
            return "1011"
        elif input == "a":
            DiameterLogger.debug("Found a - Returning 1100")
            return "1100"
        elif input == "b":
            DiameterLogger.debug("Found b - Returning 1101")
            return "1101"
        elif input == "c":
            DiameterLogger.debug("Found c - Returning 1100")
            return "1100"      
        else:
            binform = "{:04b}".format(int(input))
            DiameterLogger.debug("input " + str(input) + " is not a special char, converted to bin: " + str(binform))
            return (binform)

    def TBCD_encode(self, input):
        DiameterLogger.debug("TBCD_encode input value is " + str(input))
        offset = 0
        output = ''
        matches = ['*', '#', 'a', 'b', 'c']
        while offset < len(input):
            if len(input[offset:offset+2]) == 2:
                DiameterLogger.debug("processing bits " + str(input[offset:offset+2]) + " at position offset " + str(offset))
                bit = input[offset:offset+2]    #Get two digits at a time
                bit = bit[::-1]                 #Reverse them
                #Check if *, #, a, b or c
                if any(x in bit for x in matches):
                    DiameterLogger.debug("Special char in bit " + str(bit))
                    new_bit = ''
                    new_bit = new_bit + str(self.TBCD_special_chars(bit[0]))
                    new_bit = new_bit + str(self.TBCD_special_chars(bit[1]))
                    DiameterLogger.debug("Final bin output of new_bit is " + str(new_bit))
                    bit = hex(int(new_bit, 2))[2:]      #Get Hex value
                    DiameterLogger.debug("Formatted as Hex this is " + str(bit))
                output = output + bit
                offset = offset + 2
            else:
                #If odd-length input
                last_digit = str(input[offset:offset+2])
                #Check if *, #, a, b or c
                if any(x in last_digit for x in matches):
                    DiameterLogger.debug("Special char in bit " + str(bit))
                    new_bit = ''
                    new_bit = new_bit + '1111'      #Add the F first
                    #Encode the symbol into binary and append it to the new_bit var
                    new_bit = new_bit + str(self.TBCD_special_chars(last_digit))
                    DiameterLogger.debug("Final bin output of new_bit is " + str(new_bit)) 
                    bit = hex(int(new_bit, 2))[2:]      #Get Hex value
                    DiameterLogger.debug("Formatted as Hex this is " + str(bit))
                else:
                    bit = "f" + last_digit
                offset = offset + 2
                output = output + bit
        DiameterLogger.debug("TBCD_encode final output value is " + str(output))
        return output

    def TBCD_decode(self, input):
        DiameterLogger.debug("TBCD_decode Input value is " + str(input))
        offset = 0
        output = ''
        while offset < len(input):
            if "f" not in input[offset:offset+2]:
                bit = input[offset:offset+2]    #Get two digits at a time
                bit = bit[::-1]                 #Reverse them
                output = output + bit
                offset = offset + 2
            else:   #If f in bit strip it
                bit = input[offset:offset+2]
                output = output + bit[1]
                DiameterLogger.debug("TBCD_decode output value is " + str(output))
                return output

    #Hexify the vars we got when initializing the class
    def __init__(self, OriginHost, OriginRealm, ProductName, MNC, MCC):
        self.OriginHost = self.string_to_hex(OriginHost)
        self.OriginRealm = self.string_to_hex(OriginRealm)
        self.ProductName = self.string_to_hex(ProductName)
        self.MNC = str(MNC)
        self.MCC = str(MCC)

        DiameterLogger.info("Initialized Diameter for " + str(OriginHost) + " at Realm " + str(OriginRealm) + " serving as Product Name " + str(ProductName))
        DiameterLogger.info("PLMN is " + str(MCC) + "/" + str(MNC))

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
        logtool.RedisIncrimenter('generate_avp_count')
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
            DiameterLogger.debug("Rounded value is " + str(rounded_value))
            DiameterLogger.debug("Has " + str( int( rounded_value - avp_length)) + " bytes of padding")
            avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)


        
        avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_vendorid) + str(avp_content) + str(avp_padding)
        logtool.RedisIncrimenter('generate_vendor_avp')
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
        logtool.RedisIncrimenter('diameter_packet_count')
        return packet_hex

    def decode_diameter_packet(self, data):
        print(data)
        packet_vars = {}
        avps = []
        
        if type(data) is bytes:
            data = data.hex()


        packet_vars['packet_version'] = data[0:2]
        packet_vars['length'] = int(data[2:8], 16)
        packet_vars['flags'] = data[8:10]
        packet_vars['flags_bin'] = bin(int(data[8:10], 16))[2:].zfill(8)
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
        logtool.RedisIncrimenter('diameter_packet_decode_count')
        return packet_vars, avps

    def decode_avp_packet(self, data):                   

        if len(data) <= 8:
            #if length is less than 8 it is too short to be an AVP and is most likely the data from the last AVP being attempted to be parsed as another AVP
            raise ValueError("Length of data is too short to be valid AVP")

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
            if str(e) == "invalid literal for int() with base 16: ''":
                logging.debug("AVP length 0 error")
                pass
            elif str(e) == "Length of data is too short to be valid AVP":
                logging.debug("AVP length 0 error v2")
                pass
            else:
                DiameterLogger.debug("failed to decode sub-avp - error: " + str(e))
                pass


        remaining_avps = data[(avp_vars['avp_length']*2)+avp_vars['padding']:]  #returns remaining data in avp string back for processing again
        logtool.RedisIncrimenter('diameter_decode_avp_count')
        return avp_vars, remaining_avps

    def get_avp_data(self, avps, avp_code):               #Loops through list of dicts generated by the packet decoder, and returns the data for a specific AVP code in list (May be more than one AVP with same code but different data)
        misc_data = []
        for keys in avps:
            if keys['avp_code'] == avp_code:
                misc_data.append(keys['misc_data'])
        return misc_data

    def decode_diameter_packet_length(self, data):
        packet_vars = {}
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

    #### Diameter Answers ####

    #Capabilities Exchange Answer
    def Answer_257(self, packet_vars, avps, recv_ip):
        logtool.RedisIncrimenter('Answer_257_attempt_count')
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                 #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(264, 40, self.OriginHost)                                          #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                         #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
            if avps_to_check['avp_code'] == 278:
                avp += self.generate_avp(278, 40, self.AVP_278_Origin_State_Incriment(avps))        #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
        for host in yaml_config['hss']['bind_ip']:                                                  #Loop through all IPs from Config and add to response
            avp += self.generate_avp(257, 40, self.ip_to_hex(host))                                 #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
        avp += self.generate_avp(266, 40, "00000000")                                               #Vendor-Id
        avp += self.generate_avp(269, "00", self.ProductName)                                       #Product-Name

        #avp += self.generate_avp(267, 40, "000027d9")                                               #Firmware-Revision

        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777252),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S13)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777291),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (SLh)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777217),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Sh)       
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777236),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Rx)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777238),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx)
        avp += self.generate_avp(258, 40, format(int(10),"x").zfill(8))                                  #Auth-Application-ID - Diameter CER
        avp += self.generate_avp(265, 40, format(int(5535),"x").zfill(8))                                #Supported-Vendor-ID (3GGP v2)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(265, 40, format(int(13019),"x").zfill(8))                               #Supported-Vendor-ID 13019 (ETSI)
        response = self.generate_diameter_packet("01", "00", 257, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet       
        logtool.RedisIncrimenter('Answer_257_success_count')
        DiameterLogger.debug("Successfully Generated CEA")
        return response

    #Device Watchdog Answer                                                 
    def Answer_280(self, packet_vars, avps): 
        logtool.RedisIncrimenter('Answer_280_attempt_count')
        
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
            if avps_to_check['avp_code'] == 278:                                
                avp += self.generate_avp(278, 40, self.AVP_278_Origin_State_Incriment(avps))                  #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
        response = self.generate_diameter_packet("01", "00", 280, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_280_success_count')
        DiameterLogger.debug("Successfully Generated DWA")
        orignHost = self.get_avp_data(avps, 264)[0]                         #Get OriginHost from AVP
        orignHost = binascii.unhexlify(orignHost).decode('utf-8')           #Format it
        return response

    #Disconnect Peer Answer    
    def Answer_282(self, packet_vars, avps):                                                      
        logtool.RedisIncrimenter('Answer_282_attempt_count')
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, "000007d1")                                                    #Result Code (DIAMETER_SUCCESS (2001))
        response = self.generate_diameter_packet("01", "00", 282, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_282_success_count')
        DiameterLogger.debug("Successfully Generated DPA")
        return response

    #3GPP S6a/S6d Update Location Answer
    def Answer_16777251_316(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777251_316_attempt_count')
        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777251),"x").zfill(8))   #Auth-Application-ID Relay
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)                                  #AVP: Auth-Application-Id(258) l=12 f=-M- val=3GPP S6a/S6d (16777251)  


        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "1c000607")             #Feature-List Flags
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP


        #APNs from DB
        APN_Configuration = ''
        imsi = self.get_avp_data(avps, 1)[0]                                                            #Get IMSI from User-Name AVP in request
        imsi = binascii.unhexlify(imsi).decode('utf-8')                                                  #Convert IMSI
        try:
            subscriber_details = database.Get_Subscriber(imsi)                                               #Get subscriber details
            DiameterLogger.debug("Got back subscriber_details: " + str(subscriber_details))
        except ValueError as e:
            DiameterLogger.error("failed to get data backfrom database for imsi " + str(imsi))
            DiameterLogger.error("Error is " + str(e))
            DiameterLogger.error("Responding with DIAMETER_ERROR_USER_UNKNOWN")
            avp += self.generate_avp(268, 40, self.int_to_hex(5001, 4))
            response = self.generate_diameter_packet("01", "40", 316, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            DiameterLogger.info("Diameter user unknown - Sending ULA with DIAMETER_ERROR_USER_UNKNOWN")
            return response
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            DiameterLogger.critical(message)
            DiameterLogger.critical("Unhandled general exception when getting subscriber details for IMSI " + str(imsi))
            raise

        #Store MME Location into Database
        OriginHost = self.get_avp_data(avps, 264)[0]                          #Get OriginHost from AVP
        OriginHost = binascii.unhexlify(OriginHost).decode('utf-8')      #Format it
        DiameterLogger.debug("Subscriber is served by MME " + str(OriginHost))
        database.Update_Serving_MME(imsi, OriginHost)


        #Boilerplate AVPs
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                      #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State    
        avp += self.generate_vendor_avp(1406, "c0", 10415, "00000001")                                   #ULA Flags


        #Subscription Data: 
        subscription_data = ''
        subscription_data += self.generate_vendor_avp(1426, "c0", 10415, "00000000")                     #Access Restriction Data
        subscription_data += self.generate_vendor_avp(1424, "c0", 10415, "00000000")                     #Subscriber-Status (SERVICE_GRANTED)
        subscription_data += self.generate_vendor_avp(1417, "c0", 10415, self.int_to_hex(int(subscriber_details['nam']), 4))                     #Network-Access-Mode (PACKET_AND_CIRCUIT)

        #AMBR is a sub-AVP of Subscription Data
        AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
        ue_ambr_ul = int(subscriber_details['ue_ambr_ul'])
        ue_ambr_dl = int(subscriber_details['ue_ambr_dl'])
        AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(ue_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
        AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(ue_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
        subscription_data += self.generate_vendor_avp(1435, "c0", 10415, AMBR)                           #Add AMBR AVP in two sub-AVPs


        subscription_data += self.generate_vendor_avp(1619, "80", 10415, self.int_to_hex(int(subscriber_details['subscribed_rau_tau_timer']), 4))                                   #Subscribed-Periodic-RAU-TAU-Timer (value 720)


        #APN Configuration Profile is a sub AVP of Subscription Data
        APN_Configuration_Profile = ''
        APN_Configuration_Profile += self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(1, 4))     #Context Identifier for default APN (First APN is default in our case)
        APN_Configuration_Profile += self.generate_vendor_avp(1428, "c0", 10415, self.int_to_hex(0, 4))     #All-APN-Configurations-Included-Indicator

        #Split the APN list into a list
        apn_list = subscriber_details['apn_list'].split(',')
        DiameterLogger.debug("Current APN List: " + str(apn_list))
        #Remove the default APN from the list
        try:
            apn_list.remove(str(subscriber_details['default_apn']))
        except:
            DiameterLogger.debug("Failed to remove default APN (" + str(subscriber_details['default_apn']) + " from APN List")
            pass
        #Add default APN in first position
        apn_list.insert(0, str(subscriber_details['default_apn']))

        DiameterLogger.debug("APN list: " + str(apn_list))
        APN_context_identifer_count = 1
        for apn_id in apn_list:
            #Per APN Setup
            DiameterLogger.debug("Processing APN ID " + str(apn_id))
            try:
                apn_data = database.Get_APN(apn_id)
            except:
                DiameterLogger.error("Failed to get APN " + str(apn_id))
                continue
            APN_Service_Selection = self.generate_avp(493, "40",  self.string_to_hex(str(apn_data['apn'])))

            DiameterLogger.debug("Setting APN Configuration Profile")
            #Sub AVPs of APN Configuration Profile
            APN_context_identifer = self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(APN_context_identifer_count, 4))
            APN_PDN_type = self.generate_vendor_avp(1456, "c0", 10415, self.int_to_hex(0, 4))
            
            DiameterLogger.debug("Setting APN AMBR")
            #AMBR
            AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
            apn_ambr_ul = int(apn_data['apn_ambr_ul'])
            apn_ambr_dl = int(apn_data['apn_ambr_dl'])
            AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(apn_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
            AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(apn_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
            APN_AMBR = self.generate_vendor_avp(1435, "c0", 10415, AMBR)

            DiameterLogger.debug("Setting APN Allocation-Retention-Priority")
            #AVP: Allocation-Retention-Priority(1034) l=60 f=V-- vnd=TGPP
            AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(apn_data['arp_priority']), 4))
            AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(apn_data['arp_preemption_capability']), 4))
            AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "c0", 10415, self.int_to_hex(int(apn_data['arp_preemption_vulnerability']), 4))
            AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
            AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(int(apn_data['qci']), 4))
            APN_EPS_Subscribed_QoS_Profile = self.generate_vendor_avp(1431, "c0", 10415, AVP_QoS + AVP_ARP)


            #If static UE IP is specified - ToDo Fix This
            # try:
            #     Served_Party_Address = ""
            #     apn_ip = apn_profile['ue']['addr']
            #     DiameterLogger.debug("Found static IP for UE " + str(apn_ip))
            #     Served_Party_Address = self.generate_vendor_avp(848, "c0", 10415, self.ip_to_hex(apn_ip))
            # except:
            #     Served_Party_Address = ""
            #if 'PDN_GW_Allocation_Type' in apn_profile:
            #     DiameterLogger.info("PDN_GW_Allocation_Type present, value " + str(apn_profile['PDN_GW_Allocation_Type']))
            #     PDN_GW_Allocation_Type = self.generate_vendor_avp(1438, 'c0', 10415, self.int_to_hex(int(apn_profile['PDN_GW_Allocation_Type']), 4))
            #     DiameterLogger.info("PDN_GW_Allocation_Type value is " + str(PDN_GW_Allocation_Type))
            # else:
            #     PDN_GW_Allocation_Type = ''
            # if 'VPLMN_Dynamic_Address_Allowed' in apn_profile:
            #     DiameterLogger.info("VPLMN_Dynamic_Address_Allowed present, value " + str(apn_profile['VPLMN_Dynamic_Address_Allowed']))
            #     VPLMN_Dynamic_Address_Allowed = self.generate_vendor_avp(1432, 'c0', 10415, self.int_to_hex(int(apn_profile['VPLMN_Dynamic_Address_Allowed']), 4))
            #     DiameterLogger.info("VPLMN_Dynamic_Address_Allowed value is " + str(VPLMN_Dynamic_Address_Allowed))
            # else:
            #     VPLMN_Dynamic_Address_Allowed = ''            
            PDN_GW_Allocation_Type = ''
            Served_Party_Address = ""
            VPLMN_Dynamic_Address_Allowed = ''

            #If static SMF / PGW-C defined
            if apn_data['pgw_address'] is not None:
                DiameterLogger.info("MIP6-Agent-Info present (Static SMF/PGW-C), value " + str(apn_data['pgw_address']))
                MIP_Home_Agent_Address = self.generate_avp(334, '40', self.ip_to_hex(apn_data['pgw_address']))
                MIP6_Agent_Info = self.generate_avp(486, '40', MIP_Home_Agent_Address)
            else:
                MIP6_Agent_Info = ''

            APN_Configuration_AVPS = APN_context_identifer + APN_PDN_type + APN_AMBR + APN_Service_Selection \
                + APN_EPS_Subscribed_QoS_Profile + Served_Party_Address + MIP6_Agent_Info + PDN_GW_Allocation_Type + VPLMN_Dynamic_Address_Allowed
            
            APN_Configuration += self.generate_vendor_avp(1430, "c0", 10415, APN_Configuration_AVPS)
            
            #Incriment Context Identifier Count to keep track of how many APN Profiles returned
            APN_context_identifer_count = APN_context_identifer_count + 1  
            DiameterLogger.debug("Processed APN ID " + str(apn_id))
        
        subscription_data += self.generate_vendor_avp(1429, "c0", 10415, APN_Configuration_Profile + APN_Configuration)

        try:
            DiameterLogger.debug("MSISDN is " + str(subscriber_details['msisdn']) + " - adding in ULA")
            msisdn_avp = self.generate_vendor_avp(701, 'c0', 10415, self.TBCD_encode(str(subscriber_details['msisdn'])))                     #MSISDN
            DiameterLogger.debug(msisdn_avp)
            subscription_data += msisdn_avp
        except Exception as E:
            DiameterLogger.error("Failed to populate MSISDN in ULA due to error " + str(E))

        if 'RAT_freq_priorityID' in subscriber_details:
            DiameterLogger.debug("RAT_freq_priorityID is " + str(subscriber_details['RAT_freq_priorityID']) + " - Adding in ULA")
            rat_freq_priorityID = self.generate_vendor_avp(1440, "C0", 10415, self.int_to_hex(int(subscriber_details['RAT_freq_priorityID']), 4))                              #RAT-Frequency-Selection-Priority ID
            DiameterLogger.debug("Adding rat_freq_priorityID: " + str(rat_freq_priorityID))
            subscription_data += rat_freq_priorityID

        if 'charging_characteristics' in subscriber_details:
            DiameterLogger.debug("3gpp-charging-characteristics " + str(subscriber_details['charging_characteristics']) + " - Adding in ULA")
            _3gpp_charging_characteristics = self.generate_vendor_avp(13, "80", 10415, str(subscriber_details['charging_characteristics']))
            subscription_data += _3gpp_charging_characteristics
            DiameterLogger.debug("Adding _3gpp_charging_characteristics: " + str(_3gpp_charging_characteristics))

        #ToDo - Fix this  
        # if 'APN_OI_replacement' in subscriber_details:
        #     DiameterLogger.debug("APN_OI_replacement " + str(subscriber_details['APN_OI_replacement']) + " - Adding in ULA")
        #     subscription_data += self.generate_vendor_avp(1427, "C0", 10415, self.string_to_hex(str(subscriber_details['APN_OI_replacement'])))

        avp += self.generate_vendor_avp(1400, "c0", 10415, subscription_data)                            #Subscription-Data

        response = self.generate_diameter_packet("01", "40", 316, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777251_316_success_count')


        DiameterLogger.debug("Successfully Generated ULA")
        return response

    #3GPP S6a/S6d Authentication Information Answer
    def Answer_16777251_318(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777251_318_attempt_count')

        imsi = self.get_avp_data(avps, 1)[0]                                                             #Get IMSI from User-Name AVP in request
        imsi = binascii.unhexlify(imsi).decode('utf-8')                                                  #Convert IMSI
        plmn = self.get_avp_data(avps, 1407)[0]                                                          #Get PLMN from User-Name AVP in request

        try:
            subscriber_details = database.Get_Subscriber(imsi)                                               #Get subscriber details
        except ValueError as e:
            DiameterLogger.info("Minor getting subscriber details for IMSI " + str(imsi))
            DiameterLogger.info(e)
            #Handle if the subscriber is not present in HSS return "DIAMETER_ERROR_USER_UNKNOWN"
            logtool.RedisIncrimenter('S6a_user_unknown_count')

            DiameterLogger.info("Subscriber " + str(imsi) + " is unknown in database")
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
            avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
            response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            DiameterLogger.critical(message)
            DiameterLogger.critical("Unhandled general exception when getting subscriber details for IMSI " + str(imsi))
            raise

            

        requested_vectors = 1
        for avp in avps:
            if avp['avp_code'] == 1408:
                DiameterLogger.debug("AVP: Requested-EUTRAN-Authentication-Info(1408) l=44 f=VM- vnd=TGPP")
                EUTRAN_Authentication_Info = avp['misc_data']
                DiameterLogger.debug("EUTRAN_Authentication_Info is " + str(EUTRAN_Authentication_Info))
                for sub_avp in EUTRAN_Authentication_Info:
                    #If resync request
                    if sub_avp['avp_code'] == 1411:
                        DiameterLogger.debug("Re-Synchronization required - SQN is out of sync")
                        logtool.RedisIncrimenter('S6a_resync_count')
                        auts = str(sub_avp['misc_data'])[32:]
                        rand = str(sub_avp['misc_data'])[:32]
                        #rand = subscriber_details['RAND']
                        rand = binascii.unhexlify(rand)
                        #Calculate correct SQN
                        database.Get_Vectors_AuC(subscriber_details['auc_id'], "air_resync", auts=auts, rand=rand)

                    #Get number of requested vectors
                    if sub_avp['avp_code'] == 1410:
                        DiameterLogger.debug("Raw value of requested vectors is " + str(sub_avp['misc_data']))
                        requested_vectors = int(sub_avp['misc_data'], 16)

        DiameterLogger.debug("Generating " + str(requested_vectors) + " vectors as requested")
        eutranvector_complete = ''
        while requested_vectors != 0:
            DiameterLogger.debug("Generating vector number " + str(requested_vectors))
            plmn = self.get_avp_data(avps, 1407)[0]                                                     #Get PLMN from request
            vector_dict = database.Get_Vectors_AuC(subscriber_details['auc_id'], "air", plmn=plmn)
            eutranvector = ''                                                                           #This goes into the payload of AVP 10415 (Authentication info)
            eutranvector += self.generate_vendor_avp(1419, "c0", 10415, self.int_to_hex(requested_vectors, 4))
            eutranvector += self.generate_vendor_avp(1447, "c0", 10415, vector_dict['rand'])                                #And is made up of other AVPs joined together with RAND
            eutranvector += self.generate_vendor_avp(1448, "c0", 10415, vector_dict['xres'])                                #XRes
            eutranvector += self.generate_vendor_avp(1449, "c0", 10415, vector_dict['autn'])                                #AUTN
            eutranvector += self.generate_vendor_avp(1450, "c0", 10415, vector_dict['kasme'])                               #And KASME

            requested_vectors = requested_vectors - 1
            eutranvector_complete += self.generate_vendor_avp(1414, "c0", 10415, eutranvector)                         #Put EUTRAN vectors in E-UTRAN-Vector AVP

        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_vendor_avp(1413, "c0", 10415, eutranvector_complete)                                 #Authentication-Info (3GPP)                                      
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")
        #avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        
        response = self.generate_diameter_packet("01", "40", 318, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet        logtool.RedisIncrimenter('Answer_16777251_318_success_count')
        DiameterLogger.debug("Successfully Generated AIA")
        DiameterLogger.debug(response)
        return response

    #Purge UE Answer (PUA)
    def Answer_16777251_321(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777251_321_attempt_count')
        
        imsi = self.get_avp_data(avps, 1)[0]                                                             #Get IMSI from User-Name AVP in request
        imsi = binascii.unhexlify(imsi).decode('utf-8')

        avp = ''
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                      #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)        
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

        #1442 - PUA-Flags
        avp += self.generate_vendor_avp(1442, "c0", 10415, self.int_to_hex(1, 4))

        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "1c000607")             #Feature-List Flags
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP


        response = self.generate_diameter_packet("01", "40", 321, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777251_321_success_count')
        

        database.Update_Serving_MME(imsi, None)
        DiameterLogger.debug("Successfully Generated PUA")
        return response

    #Notify Answer (NOA)
    def Answer_16777251_323(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777251_323_attempt_count')
        avp = ''
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                      #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)        
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_avp(258, 40, format(int(16777251),"x").zfill(8))   #Auth-Application-ID Relay
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP
        response = self.generate_diameter_packet("01", "40", 323, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777251_323_success_count')
        DiameterLogger.debug("Successfully Generated PUA")
        return response

    #3GPP Gx Credit Control Answer
    def Answer_16777238_272(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777238_272_attempt_count')
        CC_Request_Type = self.get_avp_data(avps, 416)[0]
        CC_Request_Number = self.get_avp_data(avps, 415)[0]
        #Called Station ID
        DiameterLogger.debug("Attempting to find APN in CCR")
        apn = bytes.fromhex(self.get_avp_data(avps, 30)[0]).decode('utf-8')
        DiameterLogger.debug("CCR for APN " + str(apn))

        OriginHost = self.get_avp_data(avps, 264)[0]                          #Get OriginHost from AVP
        OriginHost = binascii.unhexlify(OriginHost).decode('utf-8')      #Format it

        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
        avp += self.generate_avp(258, 40, "01000016")                                                    #Auth-Application-Id (3GPP Gx 16777238)
        avp += self.generate_avp(416, 40, format(int(CC_Request_Type),"x").zfill(8))                     #CC-Request-Type (ToDo - Check dyanmically generating)
        avp += self.generate_avp(415, 40, format(int(CC_Request_Number),"x").zfill(8))                   #CC-Request-Number (ToDo - Check dyanmically generating)
        

        #Get Subscriber info from Subscription ID
        for SubscriptionIdentifier in self.get_avp_data(avps, 443):
            for UniqueSubscriptionIdentifier in SubscriptionIdentifier:
                DiameterLogger.debug("Evaluating UniqueSubscriptionIdentifier AVP " + str(UniqueSubscriptionIdentifier) + " to find IMSI")
                if UniqueSubscriptionIdentifier['avp_code'] == 444:
                    imsi = binascii.unhexlify(UniqueSubscriptionIdentifier['misc_data']).decode('utf-8')
                    DiameterLogger.debug("Found IMSI " + str(imsi))

        DiameterLogger.info("SubscriptionID: " + str(self.get_avp_data(avps, 443)))
        try:
            DiameterLogger.info("Getting subscriber info for IMSI " + str(imsi) + " from database")                                            #Get subscriber details
            ChargingRules = database.Get_Charging_Rules(imsi=imsi, apn=apn)
            DiameterLogger.info("Got Charging Rules: " + str(ChargingRules))

        except:
            #Handle if the subscriber is not present in HSS return "DIAMETER_ERROR_USER_UNKNOWN"
            DiameterLogger.debug("Subscriber " + str(imsi) + " unknown in HSS for CCR - Check Charging Rule assigned to APN is set and exists")


        if int(CC_Request_Type) == 1:
            DiameterLogger.info("Request type for CCA is 1 - Initial")

            
            try:
                ue_ip = self.get_avp_data(avps, 8)[0]
                ue_ip = str(self.hex_to_ip(ue_ip))
            except Exception as E:
                DiameterLogger.error("Failed to get UE IP")
                DiameterLogger.error(E)
                ue_ip = 'Failed to Decode / Get UE IP'


            #Default EPS QoS (From CCR-I)
            default_EPS_QoS = self.get_avp_data(avps, 1049)[0][8:]
            avp += self.generate_vendor_avp(1049, "c0", 10415, default_EPS_QoS)

                                                                                                    #Supported-Features(628) (Gx feature list)
            avp += self.generate_vendor_avp(628, "80", 10415, "0000027580000010000028af000000010000027680000010000028af0000000b")
            DiameterLogger.info("Creating QoS Information")
                                                                                                    #QoS-Information
            QoS_Information = self.generate_vendor_avp(1041, "80", 10415, "009c4000")                                                                  
            QoS_Information += self.generate_vendor_avp(1040, "80", 10415, "009c4000")
            DiameterLogger.info("Created both QoS AVPs")
            DiameterLogger.info("Populated QoS_Infomration")
            avp += self.generate_vendor_avp(1016, "80", 10415, QoS_Information)
            DiameterLogger.info("Added to AVP List")
            DiameterLogger.debug("QoS Information: " + str(QoS_Information))                                                                                 
            
            #If database returned an existing ChargingRule defintion
            try:
                DiameterLogger.debug(ChargingRules)

                #Install Charging Rules
                DiameterLogger.info("Naming Charging Rule")
                Charging_Rule_Name = self.generate_vendor_avp(1005, "80", 10415, str(binascii.hexlify(str.encode(str(ChargingRules['rule_name']))),'ascii'))
                DiameterLogger.info("Named Charging Rule")

                #Populate all Flow Information AVPs
                Flow_Information = ''
                for tft in ChargingRules['tft']:
                    DiameterLogger.info(tft)
                    #Valid Values for Flow_Direction: 0- Unspecified, 1 - Downlink, 2 - Uplink, 3 - Bidirectional
                    Flow_Direction = self.generate_vendor_avp(1080, "80", 10415, self.int_to_hex(tft['direction'], 4))
                    Flow_Description = self.generate_vendor_avp(507, "c0", 10415, str(binascii.hexlify(str.encode(tft['tft_string'])),'ascii'))
                    Flow_Information += self.generate_vendor_avp(1058, "80", 10415, Flow_Direction + Flow_Description)

                Flow_Status = self.generate_vendor_avp(511, "c0", 10415, self.int_to_hex(2, 4))

                DiameterLogger.info("Defining QoS information")
                #QCI 
                QCI += self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(1, 4))

                #ARP
                DiameterLogger.info("Defining ARP information")
                AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(ChargingRules['arp_priority']), 4))
                AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(ChargingRules['arp_preemption_capability']), 4))
                AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "c0", 10415, self.int_to_hex(int(ChargingRules['arp_preemption_vulnerability']), 4))
                ARP += self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)

                DiameterLogger.info("Defining MBR information")
                #Max Requested Bandwidth
                Bandwidth_info = ''
                Bandwidth_info += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(int(ChargingRules['mbr_ul']), 4))
                Bandwidth_info += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(int(ChargingRules['mbr_dl']), 4))
                DiameterLogger.info("Defining GBR information")
                
                #GBR
                if int(ChargingRules['gbr_ul']) != 0:
                    Bandwidth_info += self.generate_vendor_avp(1026, "c0", 10415, self.int_to_hex(int(ChargingRules['gbr_ul']), 4))
                if int(ChargingRules['gbr_dl']) != 0:                
                    Bandwidth_info += self.generate_vendor_avp(1025, "c0", 10415, self.int_to_hex(int(ChargingRules['gbr_dl']), 4))

                #Populate QoS Information
                avp += self.generate_vendor_avp(1016, "80", 10415, QCI + ARP + Bandwidth_info)

                #Precedence
                DiameterLogger.info("Defining Precedence information")
                Precedence = self.generate_vendor_avp(1010, "c0", 10415, self.int_to_hex(ChargingRules['precedence'], 4))
                
                #Complete Charging Rule Defintion
                DiameterLogger.info("Collating ChargingRuleDef")
                ChargingRuleDef = Charging_Rule_Name + Flow_Information + Flow_Status + QoS_Information + Precedence
                ChargingRuleDef = self.generate_vendor_avp(1003, "c0", 10415, ChargingRuleDef)

                #Charging Rule Install
                DiameterLogger.info("Collating ChargingRuleDef")
                avp += self.generate_vendor_avp(1001, "c0", 10415, ChargingRuleDef)

                #Store PGW location into Database
                database.Update_Serving_APN(imsi=imsi, apn=apn, pcrf_session_id=binascii.unhexlify(session_id).decode(), serving_pgw=OriginHost, ue_ip=ue_ip)
            except Exception as E:
                DiameterLogger.debug("Error in populating dynamic charging rules: " + str(E))

        elif int(CC_Request_Type) == 3:
            DiameterLogger.info("Request type for CCA is 3 - Termination")
            if ChargingRules:
                database.Update_Serving_APN(imsi=imsi, apn=apn, pcrf_session_id=binascii.unhexlify(session_id).decode(), serving_pgw=None, ue_ip=None)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
        response = self.generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777238_272_success_count')
        return response

    #3GPP Cx User Authentication Answer
    def Answer_16777216_300(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777216_300_attempt_count')
        
        avp = ''                                                                                         #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        
        avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode("sip:scscf.mnc" + str(self.MNC).zfill(3) + ".mcc" + str(self.MCC).zfill(3) + ".3gppnetwork.org")),'ascii'))


        experimental_avp = ''                                                                                           #New empty avp for storing avp 297 contents
        experimental_avp = experimental_avp + self.generate_avp(266, 40, format(int(10415),"x").zfill(8))               #3GPP Vendor ID

        #The spec specifies the DIAMETER_FIRST_REGISTRATION to be used on the first registration, DIAMETER_SUBSEQUENT_REGISTRATION on subsequent and DIAMETER_UNREGISTERED_SERVICE when clearing registration.
        #ToDo - Impliment this properly
        experimental_avp = experimental_avp + self.generate_avp(298, 40, format(int(2001),"x").zfill(8))                #Expiremental Result Code 298 val DIAMETER_FIRST_REGISTRATION
        #experimental_avp = experimental_avp + self.generate_avp(298, 40, format(int(2004),"x").zfill(8))                #Expiremental Result Code 298 val DIAMETER_SUBSEQUENT_REGISTRATION
        #experimental_avp = experimental_avp + self.generate_avp(298, 40, format(int(2005),"x").zfill(8))                #Expiremental Result Code 298 val DIAMETER_UNREGISTERED_SERVICE
        
        
        avp += self.generate_avp(297, 40, experimental_avp)                                                             #Expermental-Result
        
        response = self.generate_diameter_packet("01", "40", 300, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777216_300_success_count')
        
        return response


    #3GPP Cx Server Assignment Answer
    def Answer_16777216_301(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777216_301_attempt_count')

        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        #ToDo - Make this Dynamic
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx

        try:
            DiameterLogger.info("Checking if username present")
            username = self.get_avp_data(avps, 601)[0]                                                     
            username = binascii.unhexlify(username).decode('utf-8')
            DiameterLogger.info("Username AVP is present, value is " + str(username))
            imsi = username.split('@')[0]   #Strip Domain
            domain = username.split('@')[1] #Get Domain Part
            imsi = imsi[4:]                 #Strip SIP: from start of string
            DiameterLogger.debug("Extracted imsi: " + str(imsi) + " now checking backend for this IMSI")
            ims_subscriber_details = database.Get_IMS_Subscriber(imsi=imsi)
            DiameterLogger.debug("Got subscriber details: " + str(ims_subscriber_details))
        except Exception as E:
            DiameterLogger.error("Threw Exception: " + str(E))
            DiameterLogger.error("No known MSISDN or IMSI in Answer_16777216_301() input")
            result_code = 5005
            #Experimental Result AVP
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            response = self.generate_diameter_packet("01", "40", 301, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response

        avp += self.generate_avp(1, 40, str(binascii.hexlify(str.encode(str(imsi) + '@' + str(domain))),'ascii'))
        #Cx-User-Data (XML)
        
        #This loads a Jinja XML template as the default iFC
        templateLoader = jinja2.FileSystemLoader(searchpath="./")
        templateEnv = jinja2.Environment(loader=templateLoader)
        DiameterLogger.debug("Loading iFC from path " + str(ims_subscriber_details['ifc_path']))
        template = templateEnv.get_template(ims_subscriber_details['ifc_path'])
        
        #These variables are passed to the template for use
        ims_subscriber_details['mnc'] = self.MNC.zfill(3)
        ims_subscriber_details['mcc'] = self.MCC.zfill(3)

        xmlbody = template.render(iFC_vars=ims_subscriber_details)  # this is where to put args to the template renderer
        avp += self.generate_vendor_avp(606, "c0", 10415, str(binascii.hexlify(str.encode(xmlbody)),'ascii'))
        #Charging Information
        avp += self.generate_vendor_avp(618, "c0", 10415, "0000026dc000001b000028af7072695f6363665f6164647265737300")
        avp += self.generate_avp(268, 40, "000007d1")                                                   #DIAMETER_SUCCESS
        response = self.generate_diameter_packet("01", "40", 301, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777216_301_success_count')
        return response    


    #3GPP Cx Location Information Answer
    def Answer_16777216_302(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777216_302_attempt_count')
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth Session State
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        username = self.get_avp_data(avps, 601)[0]
        username = binascii.unhexlify(username).decode('utf-8')
        DiameterLogger.debug("Public-Identity for Location Information Request is: " + str(username))
        avp += self.generate_vendor_avp(602, "c0", 10415, str(binascii.hexlify(str.encode("sip:scscf.mnc" + str(self.MNC).zfill(3) + ".mcc" + str(self.MCC).zfill(3) + ".3gppnetwork.org:5060")),'ascii'))
        avp += self.generate_avp(268, 40, "000007d1")                                                   #DIAMETER_SUCCESS
        response = self.generate_diameter_packet("01", "40", 302, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777216_302_success_count')
        
        return response

    #3GPP Cx Multimedia Authentication Answer
    def Answer_16777216_303(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777216_303_attempt_count')
        username = self.get_avp_data(avps, 601)[0]                                                     
        username = binascii.unhexlify(username).decode('utf-8')
        imsi = username.split('@')[0]   #Strip Domain
        domain = username.split('@')[1] #Get Domain Part
        imsi = imsi[4:]                 #Strip SIP: from start of string
        DiameterLogger.debug("Got MAR for public_identity : " + str(username))

        avp = ''                                                                                    #Initiate empty var AVP
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth Session State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm        

        try:
            subscriber_details = database.Get_Subscriber(imsi)                                               #Get subscriber details
        except:
            #Handle if the subscriber is not present in HSS return "DIAMETER_ERROR_USER_UNKNOWN"
            DiameterLogger.debug("Subscriber " + str(imsi) + " unknown in HSS for MAA")
            experimental_result = self.generate_avp(298, 40, self.int_to_hex(5001, 4))                                           #Result Code (DIAMETER ERROR - User Unknown)
            experimental_result = experimental_result + self.generate_vendor_avp(266, 40, 10415, "")
            #Experimental Result (297)
            avp += self.generate_avp(297, 40, experimental_result)
            response = self.generate_diameter_packet("01", "40", 303, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        
        mcc, mnc = imsi[0:3], imsi[3:5]
        plmn = self.EncodePLMN(mcc, mnc)
        vector_dict = database.Get_Vectors_AuC(subscriber_details['auc_id'], "sip_auth", plmn=plmn)
        
        DiameterLogger.debug("IMSI is " + str(imsi))        
        avp += self.generate_vendor_avp(601, "c0", 10415, str(binascii.hexlify(str.encode(username)),'ascii'))               #Public Identity (IMSI)
        avp += self.generate_avp(1, 40, str(binascii.hexlify(str.encode(imsi)),'ascii'))                             #Username
        


        #diameter.3GPP-SIP-Auth-Data-Items
        ##AVP Code: 613 3GPP-SIP-Item-Number
        avp_SIP_Item_Number = self.generate_vendor_avp(613, "c0", 10415, format(int(0),"x").zfill(8))
        ##AVP Code: 608 3GPP-SIP-Authentication-Scheme
        avp_SIP_Authentication_Scheme = self.generate_vendor_avp(608, "c0", 10415, str(binascii.hexlify(b'Digest-AKAv1-MD5'),'ascii'))
        ##AVP Code: 609 3GPP-SIP-Authenticate
        avp_SIP_Authenticate = self.generate_vendor_avp(609, "c0", 10415, str(binascii.hexlify(vector_dict['SIP_Authenticate']),'ascii'))   #RAND + AUTN
        
        ##AVP Code: 610 3GPP-SIP-Authorization
        avp_SIP_Authorization = self.generate_vendor_avp(610, "c0", 10415, str(binascii.hexlify(vector_dict['xres']),'ascii'))  #XRES
        
        ##AVP Code: 625 Confidentiality-Key
        avp_Confidentialility_Key = self.generate_vendor_avp(625, "c0", 10415, str(binascii.hexlify(vector_dict['ck']),'ascii'))  #CK
        
        ##AVP Code: 626 Integrity-Key
        avp_Integrity_Key = self.generate_vendor_avp(626, "c0", 10415, str(binascii.hexlify(vector_dict['ik']),'ascii'))          #IK

        
        auth_data_item = avp_SIP_Item_Number + avp_SIP_Authentication_Scheme + avp_SIP_Authenticate + avp_SIP_Authorization + avp_Confidentialility_Key + avp_Integrity_Key
        avp += self.generate_vendor_avp(612, "c0", 10415, auth_data_item)    #3GPP-SIP-Auth-Data-Item
        
        avp += self.generate_vendor_avp(607, "c0", 10415, "00000001")                                    #3GPP-SIP-Number-Auth-Items

        experimental_avp = ''                                                                                           #New empty avp for storing avp 297 contents
        experimental_avp = experimental_avp + self.generate_avp(266, 40, format(int(10415),"x").zfill(8))               #3GPP Vendor ID
        experimental_avp = experimental_avp + self.generate_avp(298, 40, format(int(2001),"x").zfill(8))                #Expiremental Result Code 298 val DIAMETER_FIRST_REGISTRATION
        avp += self.generate_avp(297, 40, experimental_avp)                                                             #Expermental-Result
        

        avp += self.generate_avp(268, 40, "000007d1")                                                   #DIAMETER_SUCCESS
        
        response = self.generate_diameter_packet("01", "40", 303, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777216_303_success_count')
        return response

    #Generate a Generic error handler with Result Code as input
    def Respond_ResultCode(self, packet_vars, avps, result_code):
        logging.error("Responding with result code " + str(result_code) + " to request with command code " + str(packet_vars['command_code']))
        logtool.RedisIncrimenter('Answer_Respond_Command_attempt_count')
        avp = ''                                                                                    #Initiate empty var AVP
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        try:
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        except:
            DiameterLogger.info("Failed to add SessionID into error")
        for avps_to_check in avps:                                                                  #Only include AVP 260 (Vendor-Specific-Application-ID) if inital request included it
            if avps_to_check['avp_code'] == 260:
                concat_subavp = ''
                for sub_avp in avps_to_check['misc_data']:
                    concat_subavp += self.generate_avp(sub_avp['avp_code'], sub_avp['avp_flags'], sub_avp['misc_data'])
                avp += self.generate_avp(260, 40, concat_subavp)        #Vendor-Specific-Application-ID
        avp += self.generate_avp(268, 40, self.int_to_hex(result_code, 4))                                                   #Response Code
        
        #Experimental Result AVP(Response Code for Failure)
        avp_experimental_result = ''
        avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
        avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))                 #AVP Experimental-Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001)
        avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)

        response = self.generate_diameter_packet("01", "60", int(packet_vars['command_code']), int(packet_vars['ApplicationId']), packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_Respond_Command_success_count')
        return response



    #3GPP Cx Registration Termination Answer
    def Answer_16777216_304(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777216_304_attempt_count')
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        vendor_id = self.generate_avp(266, 40, str(binascii.hexlify('10415'),'ascii'))
        DiameterLogger.debug("vendor_id avp: " + str(vendor_id))
        auth_application_id = self.generate_avp(248, 40, self.int_to_hex(16777252, 8))
        DiameterLogger.debug("auth_application_id: " + auth_application_id)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(268, 40, "000007d1")                                                   #Result Code - DIAMETER_SUCCESS
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth Session State        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                             #Origin Realm
                #* [ Proxy-Info ]
        proxy_host_avp = self.generate_avp(280, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        proxy_state_avp = self.generate_avp(33, "40", "0001")
        avp += self.generate_avp(284, "40", proxy_host_avp + proxy_state_avp)                 #Proxy-Info  AVP ( 284 )

        #* [ Route-Record ]
        avp += self.generate_avp(282, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        
        response = self.generate_diameter_packet("01", "40", 304, 16777216, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777216_304_success_count')
        return response

    #3GPP Sh User-Data Answer
    def Answer_16777217_306(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777217_306_attempt_count')
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID

        #Define values so we can check if they've been changed
        msisdn = None
        try:
            user_identity_avp = self.get_avp_data(avps, 700)[0]
            msisdn = self.get_avp_data(user_identity_avp, 701)[0]                                                         #Get MSISDN from AVP in request
            DiameterLogger.info("Got raw MSISDN with value " + str(msisdn))
            msisdn = self.TBCD_decode(msisdn)
            DiameterLogger.info("Got MSISDN with value " + str(msisdn))
        except:
            DiameterLogger.error("No MSISDN")

        if msisdn is not None:
                DiameterLogger.debug("Getting susbcriber location based on MSISDN")
                subscriber_details = database.Get_IMS_Subscriber(msisdn=msisdn)
                DiameterLogger.debug("Got subscriber details: " + subscriber_details)
        else:
            DiameterLogger.error("No MSISDN or IMSI in Answer_16777217_306() input")
            result_code = 5005
            #Experimental Result AVP
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            response = self.generate_diameter_packet("01", "40", 306, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        
        session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to recieved session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (No state maintained)
        
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000001")            #Vendor-Specific-Application-ID for Cx

        #Sh-User-Data (XML)
        #This loads a Jinja XML template containing the Sh-User-Data
        templateLoader = jinja2.FileSystemLoader(searchpath="./")
        templateEnv = jinja2.Environment(loader=templateLoader)
        sh_userdata_template = yaml_config['hss']['Default_Sh_UserData']
        DiameterLogger.info("Using template " + str(sh_userdata_template) + " for SH user data")
        template = templateEnv.get_template(sh_userdata_template)
        #These variables are passed to the template for use
        subscriber_details['mnc'] = self.MNC.zfill(3)
        subscriber_details['mcc'] = self.MCC.zfill(3)
        DiameterLogger.info("Rendering template with values: " + str(subscriber_details))
        xmlbody = template.render(Sh_template_vars=subscriber_details)  # this is where to put args to the template renderer
        avp += self.generate_vendor_avp(702, "c0", 10415, str(binascii.hexlify(str.encode(xmlbody)),'ascii'))
        
        avp += self.generate_avp(268, 40, "000007d1")                                                   #DIAMETER_SUCCESS

        response = self.generate_diameter_packet("01", "40", 306, 16777217, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777217_306_success_count')
        return response

    #3GPP S13 - ME-Identity-Check Answer
    def Answer_16777252_324(self, packet_vars, avps):
        logtool.RedisIncrimenter('Answer_16777252_324_attempt_count')
        avp = ''                                                                                        #Initiate empty var AVP                                                                                           #Session-ID
        session_id = self.get_avp_data(avps, 263)[0]                                                    #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                   #Set session ID to recieved session ID
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000024")           #Vendor-Specific-Application-ID for S13
        avp += self.generate_avp(268, 40, "000007d1")                                                   #Result Code - DIAMETER_SUCCESS
        avp += self.generate_avp(277, 40, "00000001")                                                   #Auth Session State        
        avp += self.generate_avp(264, 40, self.OriginHost)                                              #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                             #Origin Realm
        #Experimental Result AVP(Response Code for Failure)
        avp_experimental_result = ''
        avp_experimental_result += self.generate_vendor_avp(266, 'c0', 10415, '')                         #AVP Vendor ID
        avp_experimental_result += self.generate_avp(298, 'c0', self.int_to_hex(2001, 4))                 #AVP Experimental-Result-Code: SUCESS (2001)
        avp += self.generate_avp(297, '40', avp_experimental_result)                                      #AVP Experimental-Result(297)
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                 #Result Code (DIAMETER_SUCCESS (2001))
        response = self.generate_diameter_packet("01", "40", 324, 16777252, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    #3GPP SLh - LCS-Routing-Info-Answer
    def Answer_16777291_8388622(self, packet_vars, avps):
        avp = '' 
        session_id = self.get_avp_data(avps, 263)[0]                                                    #Get Session-ID
        avp += self.generate_avp(263, 40, session_id)                                                   #Set session    ID to recieved session ID
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777291),"x").zfill(8))   #Auth-Application-ID SLh
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                   #Auth Session State (NO_STATE_MAINTAINED)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                              #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                             #Origin Realm

        #Create list of valid AVPs
        present_avps = []
        for avp_id in avps:
            present_avps.append(avp_id['avp_code'])
        
        #Define values so we can check if they've been changed
        msisdn = None
        imsi = None

        #Try and get IMSI if present
        if 1 in present_avps:
            DiameterLogger.info("IMSI AVP is present")
            try:
                imsi = self.get_avp_data(avps, 1)[0]                                                            #Get IMSI from User-Name AVP in request
                imsi = binascii.unhexlify(imsi).decode('utf-8')                                                 #Convert IMSI
                avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                       #Username (IMSI)
                DiameterLogger.info("Got IMSI with value " + str(imsi))
            except Exception as e:
                DiameterLogger.debug("Failed to get IMSI from LCS-Routing-Info-Request")
                DiameterLogger.debug("Error was: " + str(e))
        elif 701 in present_avps:
            #Try and get MSISDN if present
            try:
                msisdn = self.get_avp_data(avps, 701)[0]                                                          #Get MSISDN from AVP in request
                DiameterLogger.info("Got MSISDN with value " + str(msisdn))
                avp += self.generate_vendor_avp(701, 'c0', 10415, self.get_avp_data(avps, 701)[0])                     #MSISDN
                DiameterLogger.info("Got MSISDN with encoded value " + str(msisdn))
                msisdn = self.TBCD_decode(msisdn)
                DiameterLogger.info("Got MSISDN with decoded value " + str(msisdn))
            except Exception as e:
                DiameterLogger.debug("Failed to get MSISDN from LCS-Routing-Info-Request")
                DiameterLogger.debug("Error was: " + str(e))
        else:
            DiameterLogger.error("No MSISDN or IMSI")

        if imsi is not None:
                DiameterLogger.debug("Getting susbcriber location based on IMSI")
                subscriber_location = database.Get_Subscriber(imsi=imsi)['serving_mme']
                DiameterLogger.debug("Got subscriber location: " + subscriber_location)
        elif msisdn is not None:
                #ToDo - Impliment
                DiameterLogger.debug("Getting susbcriber location based on MSISDN")
                subscriber_location = database.GetSubscriberLocation(msisdn=msisdn)
                DiameterLogger.debug("Got subscriber location: " + subscriber_location)
        else:
            DiameterLogger.error("No MSISDN or IMSI in Answer_16777291_8388622 input")
            result_code = 5005
            #Experimental Result AVP
            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code: SUCCESS (2001)
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            response = self.generate_diameter_packet("01", "40", 8388622, 16777291, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        
        DiameterLogger.info("Got location for subscriber: " + str(subscriber_location))

        
        if subscriber_location == None:
            #DB has no location on record for subscriber
            DiameterLogger.info("No location on record for Subscriber")
            result_code = 4201
            #DIAMETER_ERROR_ABSENT_USER (4201)
            #This result code shall be sent by the HSS to indicate that the location of the targeted user is not known at this time to
            #satisfy the requested operation. 

            avp_experimental_result = ''
            avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
            avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))          #AVP Experimental-Result-Code
            avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)
            
            response = self.generate_diameter_packet("01", "40", 8388622, 16777291, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response



        #Serving Node AVP
        avp_serving_node = ''
        avp_serving_node += self.generate_vendor_avp(2402, "c0", 10415, self.string_to_hex(subscriber_location))            #MME-Name
        avp_serving_node += self.generate_vendor_avp(2408, "c0", 10415, self.OriginRealm)                                   #MME-Realm
        avp_serving_node += self.generate_vendor_avp(2405, "c0", 10415, self.ip_to_hex('127.0.0.1'))                        #GMLC-Address
        avp += self.generate_vendor_avp(2401, "c0", 10415, avp_serving_node)                                                #Serving-Node  AVP

        #Set Result-Code
        result_code = 2001                                                                                                  #Diameter Success
        avp += self.generate_avp(268, 40, self.int_to_hex(result_code, 4))                                                  #Result Code - DIAMETER_SUCCESS

        response = self.generate_diameter_packet("01", "40", 8388622, 16777291, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response
        
    #### Diameter Requests ####

    #Capabilities Exchange Request
    def Request_257(self):
        avp = ''
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(257, 40, self.ip_to_hex(socket.gethostbyname(socket.gethostname())))         #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
        avp += self.generate_avp(266, 40, "00000000")                                                    #Vendor-Id
        avp += self.generate_avp(269, "00", self.ProductName)                                                   #Product-Name
        avp += self.generate_avp(260, 40, "000001024000000c01000023" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        avp += self.generate_avp(260, 40, "000001024000000c01000016" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx)
        avp += self.generate_avp(260, 40, "000001024000000c01000027" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (SLg)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777217),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Sh)
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
    def Request_16777251_318(self, imsi, DestinationHost, DestinationRealm):                                                             
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                                                   #Destination Realm
        #avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                                                   #Destination Host
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_vendor_avp(1408, "c0", 10415, "00000582c0000010000028af0000000100000584c0000010000028af00000001")
        mcc = str(imsi)[:3]
        mnc = str(imsi)[3:5]
        avp += self.generate_vendor_avp(1407, "c0", 10415, self.EncodePLMN(mcc, mnc))                    #Visited-PLMN-Id(1407) (Derrived from start of IMSI)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID       
        response = self.generate_diameter_packet("01", "c0", 318, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d Update Location Request (ULR)
    def Request_16777251_316(self, imsi, DestinationRealm):
        mcc = imsi[0:3]
        mnc = imsi[3:5]
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                                                   #Destination Realm
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_vendor_avp(1032, "80", 10415, self.int_to_hex(1004, 4))                    #RAT-Type val=EUTRAN (1004)
        avp += self.generate_vendor_avp(1405, "c0", 10415, "00000002")                                  #ULR-Flags val=2
        avp += self.generate_vendor_avp(1407, "c0", 10415, self.EncodePLMN(mcc, mnc))                    #Visited-PLMN-Id(1407) (Derrived from start of IMSI)
        avp += self.generate_vendor_avp(1615, "80", 10415, "00000000")                                  #E-SRVCC-Capability val=UE-SRVCC-NOT-SUPPORTED (0)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
        response = self.generate_diameter_packet("01", "c0", 316, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response
    
    #3GPP S6a/S6d Purge UE Request PUR
    def Request_16777251_321(self, imsi, DestinationRealm, DestinationHost):
        avp = ''
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))               #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                         #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                               #Destination Realm
        #avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                                #Destination Host
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")                 #Vendor-Specific-Application-ID
        response = self.generate_diameter_packet("01", "c0", 321, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d NOtify Request NOR
    def Request_16777251_323(self, imsi, DestinationRealm, DestinationHost):
        avp = ''
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_s6a'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))               #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                         #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                               #Destination Realm
        #avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                                #Destination Host
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")                 #Vendor-Specific-Application-ID
        response = self.generate_diameter_packet("01", "c0", 323, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d Cancel-Location-Request Request CLR
    def Request_16777251_317(self, imsi, DestinationRealm, DestinationHost):
        avp = ''
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_s6a'                      #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(283, 40, self.string_to_hex(DestinationRealm))                          #Destination Realm
        #avp += self.generate_avp(293, 40, self.string_to_hex(DestinationHost))                           #Destination Host
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                        #Username (IMSI)
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID
        avp += self.generate_vendor_avp(1420, "c0", 10415,  self.int_to_hex(2, 4))                       #Cancellation-Type (Subscription Withdrawl)
        response = self.generate_diameter_packet("01", "c0", 317, 16777251, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP S6a/S6d Insert Subscriber Data Request (ISD)
    def Request_16777251_319(self, packet_vars, avps, **kwargs):
        logtool.RedisIncrimenter('Request_16777251_319_attempt_count')
        avp = ''                                                                                    #Initiate empty var AVP
        avp += self.generate_avp(264, 40, self.OriginHost)                                          #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                         #Origin Realm
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_s6a'                 #Session ID generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))     #Session ID set AVP
        avp += self.generate_vendor_avp(266, 40, 10415, '')                                         #AVP Vendor ID
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                 #AVP Vendor ID
        avp += self.generate_avp(277, 40, "00000001")                                               #Auth-Session-State


        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a) 

        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "1c000607")             #Feature-List Flags
        if 'GetLocation' in kwargs:
            DiameterLogger.debug("Requsted Get Location ISD")
            #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
            SupportedFeatures = ''
            SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
            SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
            SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "18000007")             #Feature-List Flags
            avp += self.generate_vendor_avp(1490, "c0", 10415, "00000018")                        #IDR-Flags
            avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP

            try:
                user_identity_avp = self.get_avp_data(avps, 700)[0]
                DiameterLogger.info(user_identity_avp)
                msisdn = self.get_avp_data(user_identity_avp, 701)[0]                                                          #Get MSISDN from AVP in request
                msisdn = self.TBCD_decode(msisdn)
                DiameterLogger.info("Got MSISDN with value " + str(msisdn))
            except:
                DiameterLogger.error("No MSISDN present")
                return
            #Get Subscriber Location from Database
            subscriber_location = database.GetSubscriberLocation(msisdn=msisdn)
            DiameterLogger.debug("Got subscriber location: " + subscriber_location)


            DiameterLogger.info("Getting IMSI for MSISDN " + str(msisdn))
            imsi = database.Get_IMSI_from_MSISDN(msisdn)
            avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                   #Username (IMSI)

            DiameterLogger.info("Got back location data: " + str(subscriber_location))

            #Populate Destination Host & Realm
            avp += self.generate_avp(293, 40, self.string_to_hex(subscriber_location))      #Destination Host                                                      #Destination-Host
            avp += self.generate_avp(283, 40, self.string_to_hex('epc.mnc001.mcc214.3gppnetwork.org'))     #Destination Realm

        else:
            #APNs from DB
            imsi = self.get_avp_data(avps, 1)[0]                                                        #Get IMSI from User-Name AVP in request
            imsi = binascii.unhexlify(imsi).decode('utf-8')                                             #Convert IMSI
            avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                   #Username (IMSI)
            avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP
            avp += self.generate_vendor_avp(1490, "c0", 10415, "00000000")                              #IDR-Flags

            destinationHost = self.get_avp_data(avps, 264)[0]                               #Get OriginHost from AVP
            destinationHost = binascii.unhexlify(destinationHost).decode('utf-8')           #Format it
            DiameterLogger.debug("Recieved originHost to use as destinationHost is " + str(destinationHost))
            destinationRealm = self.get_avp_data(avps, 296)[0]                                #Get OriginRealm from AVP
            destinationRealm = binascii.unhexlify(destinationRealm).decode('utf-8')           #Format it
            DiameterLogger.debug("Recieved originRealm to use as destinationRealm is " + str(destinationRealm))
            avp += self.generate_avp(293, 40, self.string_to_hex(destinationHost))                                                         #Destination-Host
            avp += self.generate_avp(283, 40, self.string_to_hex(destinationRealm))

        APN_Configuration = ''

        try:
            subscriber_details = database.Get_Subscriber(imsi)                                               #Get subscriber details
        except ValueError as e:
            DiameterLogger.error("failed to get data backfrom database for imsi " + str(imsi))
            DiameterLogger.error("Error is " + str(e))
            raise
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            DiameterLogger.critical(message)
            DiameterLogger.critical("Unhandled general exception when getting subscriber details for IMSI " + str(imsi))
            raise



        #Subscription Data: 
        subscription_data = ''
        subscription_data += self.generate_vendor_avp(1426, "c0", 10415, "00000000")                     #Access Restriction Data
        subscription_data += self.generate_vendor_avp(1424, "c0", 10415, "00000000")                     #Subscriber-Status (SERVICE_GRANTED)
        subscription_data += self.generate_vendor_avp(1417, "c0", 10415, "00000000")                     #Network-Access-Mode (PACKET_AND_CIRCUIT)

        #AMBR is a sub-AVP of Subscription Data
        AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
        if 'ue_ambr_ul' in subscriber_details:
            ue_ambr_ul = int(subscriber_details['ue_ambr_ul'])
        else:
            #use default AMBR of unlimited if no value in subscriber_details
            ue_ambr_ul = 1048576000

        if 'ue_ambr_dl' in subscriber_details:
            ue_ambr_dl = int(subscriber_details['ue_ambr_dl'])
        else:
            #use default AMBR of unlimited if no value in subscriber_details
            ue_ambr_dl = 1048576000

        AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(ue_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
        AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(ue_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
        subscription_data += self.generate_vendor_avp(1435, "c0", 10415, AMBR)                           #Add AMBR AVP in two sub-AVPs

        #APN Configuration Profile is a sub AVP of Subscription Data
        APN_Configuration_Profile = ''
        APN_Configuration_Profile += self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(1, 4))     #Context Identifier
        APN_Configuration_Profile += self.generate_vendor_avp(1428, "c0", 10415, self.int_to_hex(0, 4))     #All-APN-Configurations-Included-Indicator



        apn_list = subscriber_details['pdn']
        DiameterLogger.debug("APN list: " + str(apn_list))
        APN_context_identifer_count = 1
        for apn_profile in apn_list:
            DiameterLogger.debug("Processing APN profile " + str(apn_profile))
            APN_Service_Selection = self.generate_avp(493, "40",  self.string_to_hex(str(apn_profile['apn'])))

            DiameterLogger.debug("Setting APN Configuration Profile")
            #Sub AVPs of APN Configuration Profile
            APN_context_identifer = self.generate_vendor_avp(1423, "c0", 10415, self.int_to_hex(APN_context_identifer_count, 4))
            APN_PDN_type = self.generate_vendor_avp(1456, "c0", 10415, self.int_to_hex(0, 4))
            
            DiameterLogger.debug("Setting APN AMBR")
            #AMBR
            AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
            if 'AMBR' in apn_profile:
                ue_ambr_ul = int(apn_profile['AMBR']['apn_ambr_ul'])
                ue_ambr_dl = int(apn_profile['AMBR']['apn_ambr_dl'])
            else:
                #use default AMBR of unlimited if no value in subscriber_details
                ue_ambr_ul = 50000000
                ue_ambr_dl = 100000000

            AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(ue_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
            AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(ue_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
            APN_AMBR = self.generate_vendor_avp(1435, "c0", 10415, AMBR)

            DiameterLogger.debug("Setting APN Allocation-Retention-Priority")
            #AVP: Allocation-Retention-Priority(1034) l=60 f=V-- vnd=TGPP
            AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(apn_profile['qos']['arp']['priority_level']), 4))
            AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(apn_profile['qos']['arp']['pre_emption_capability']), 4))
            AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "c0", 10415, self.int_to_hex(int(apn_profile['qos']['arp']['pre_emption_vulnerability']), 4))
            AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
            AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(int(apn_profile['qos']['qci']), 4))
            APN_EPS_Subscribed_QoS_Profile = self.generate_vendor_avp(1431, "c0", 10415, AVP_QoS + AVP_ARP)


            #If static UE IP is specified
            try:
                apn_ip = apn_profile['ue']['addr']
                DiameterLogger.debug("Found static IP for UE " + str(apn_ip))
                Served_Party_Address = self.generate_vendor_avp(848, "c0", 10415, self.ip_to_hex(apn_ip))
            except:
                Served_Party_Address = ""

            if 'MIP6-Agent-Info' in apn_profile:
                DiameterLogger.info("MIP6-Agent-Info present, value " + str(apn_profile['MIP6-Agent-Info']))
                MIP6_Destination_Host = self.generate_avp(293, '40', self.string_to_hex(str(apn_profile['MIP6-Agent-Info']['MIP6_DESTINATION_HOST'])))
                MIP6_Destination_Realm = self.generate_avp(283, '40', self.string_to_hex(str(apn_profile['MIP6-Agent-Info']['MIP6_DESTINATION_REALM'])))
                MIP6_Home_Agent_Host = self.generate_avp(348, '40', MIP6_Destination_Host + MIP6_Destination_Realm)
                MIP6_Agent_Info = self.generate_avp(486, '40', MIP6_Home_Agent_Host)
                DiameterLogger.info("MIP6 value is " + str(MIP6_Agent_Info))
            else:
                MIP6_Agent_Info = ''

            if 'PDN_GW_Allocation_Type' in apn_profile:
                DiameterLogger.info("PDN_GW_Allocation_Type present, value " + str(apn_profile['PDN_GW_Allocation_Type']))
                PDN_GW_Allocation_Type = self.generate_vendor_avp(1438, 'c0', 10415, self.int_to_hex(int(apn_profile['PDN_GW_Allocation_Type']), 4))
                DiameterLogger.info("PDN_GW_Allocation_Type value is " + str(PDN_GW_Allocation_Type))
            else:
                PDN_GW_Allocation_Type = ''

            if 'VPLMN_Dynamic_Address_Allowed' in apn_profile:
                DiameterLogger.info("VPLMN_Dynamic_Address_Allowed present, value " + str(apn_profile['VPLMN_Dynamic_Address_Allowed']))
                VPLMN_Dynamic_Address_Allowed = self.generate_vendor_avp(1432, 'c0', 10415, self.int_to_hex(int(apn_profile['VPLMN_Dynamic_Address_Allowed']), 4))
                DiameterLogger.info("VPLMN_Dynamic_Address_Allowed value is " + str(VPLMN_Dynamic_Address_Allowed))
            else:
                VPLMN_Dynamic_Address_Allowed = ''

            APN_Configuration_AVPS = APN_context_identifer + APN_PDN_type + APN_AMBR + APN_Service_Selection \
                + APN_EPS_Subscribed_QoS_Profile + Served_Party_Address + MIP6_Agent_Info + PDN_GW_Allocation_Type + VPLMN_Dynamic_Address_Allowed
            
            APN_Configuration += self.generate_vendor_avp(1430, "c0", 10415, APN_Configuration_AVPS)
            
            #Incriment Context Identifier Count to keep track of how many APN Profiles returned
            APN_context_identifer_count = APN_context_identifer_count + 1  
            DiameterLogger.debug("Processed APN profile " + str(apn_profile['apn']))
        
        subscription_data += self.generate_vendor_avp(1619, "80", 10415, self.int_to_hex(720, 4))                                   #Subscribed-Periodic-RAU-TAU-Timer (value 720)
        subscription_data += self.generate_vendor_avp(1429, "c0", 10415, APN_context_identifer + \
            self.generate_vendor_avp(1428, "c0", 10415, self.int_to_hex(0, 4)) + APN_Configuration)

        #If MSISDN is present include it in Subscription Data
        if 'msisdn' in subscriber_details:
            DiameterLogger.debug("MSISDN is " + str(subscriber_details['msisdn']) + " - adding in ULA")
            msisdn_avp = self.generate_vendor_avp(701, 'c0', 10415, str(subscriber_details['msisdn']))                     #MSISDN
            DiameterLogger.debug(msisdn_avp)
            subscription_data += msisdn_avp

        if 'RAT_freq_priorityID' in subscriber_details:
            DiameterLogger.debug("RAT_freq_priorityID is " + str(subscriber_details['RAT_freq_priorityID']) + " - Adding in ULA")
            rat_freq_priorityID = self.generate_vendor_avp(1440, "C0", 10415, self.int_to_hex(int(subscriber_details['RAT_freq_priorityID']), 4))                              #RAT-Frequency-Selection-Priority ID
            DiameterLogger.debug(rat_freq_priorityID)
            subscription_data += rat_freq_priorityID

        if '3gpp-charging-characteristics' in subscriber_details:
            DiameterLogger.debug("3gpp-charging-characteristics " + str(subscriber_details['3gpp-charging-characteristics']) + " - Adding in ULA")
            _3gpp_charging_characteristics = self.generate_vendor_avp(13, "80", 10415, self.string_to_hex(str(subscriber_details['3gpp-charging-characteristics'])))
            subscription_data += _3gpp_charging_characteristics
            DiameterLogger.debug(_3gpp_charging_characteristics)

            
        if 'APN_OI_replacement' in subscriber_details:
            DiameterLogger.debug("APN_OI_replacement " + str(subscriber_details['APN_OI_replacement']) + " - Adding in ULA")
            subscription_data += self.generate_vendor_avp(1427, "C0", 10415, self.string_to_hex(str(subscriber_details['APN_OI_replacement'])))


        if 'GetLocation' in kwargs:
            avp += self.generate_vendor_avp(1400, "c0", 10415, "")                            #Subscription-Data
        else:
            avp += self.generate_vendor_avp(1400, "c0", 10415, subscription_data)                            #Subscription-Data

        response = self.generate_diameter_packet("01", "C0", 319, 16777251, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        logtool.RedisIncrimenter('Answer_16777251_319_success_count')
        return response

    #3GPP Cx Location Information Request (LIR)
    #ToDo - Check the command code here...
    def Request_16777216_285(self, sipaor):                                                             
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        #Auth Session state
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(258, 40, format(int(16777251),"x").zfill(8))                            #Auth-Application-ID Relay (#ToDo - Investigate this AVP more)
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex(sipaor))                      #Public-Identity / SIP-AOR
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'hss.localdomain'),'ascii'))                 #Destination Host

        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000023")            #Vendor-Specific-Application-ID

        #* [ Proxy-Info ]
        proxy_host_avp = self.generate_avp(280, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        proxy_state_avp = self.generate_avp(33, "40", "0001")
        avp += self.generate_avp(284, "40", proxy_host_avp + proxy_state_avp)                 #Proxy-Info  AVP ( 284 )

        #* [ Route-Record ]
        avp += self.generate_avp(282, "40", str(binascii.hexlify(b'localdomain'),'ascii'))              
        response = self.generate_diameter_packet("01", "c0", 285, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Cx User Authentication Request (UAR)
    def Request_16777216_300(self, imsi, domain):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi + "@" + domain))                   #User-Name
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex("sip:" + imsi + "@" + domain))                 #Public-Identity
        avp += self.generate_vendor_avp(600, "c0", 10415, self.string_to_hex(domain))               #Visited Network Identifier
        response = self.generate_diameter_packet("01", "c0", 300, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Cx Server Assignment Request (SAR)
    def Request_16777216_301(self, imsi, domain):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session Session ID
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex("sip:" + imsi + "@" + domain))                 #Public-Identity
        avp += self.generate_vendor_avp(602, "c0", 10415, self.string_to_hex('sip:scscf.mnc' + self.MNC + '.mcc' + self.MCC + '.3gppnetwork.org:5060'))                 #Public-Identity
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi + "@" + domain))                   #User-Name
        avp += self.generate_vendor_avp(614, "c0", 10415, format(int(1),"x").zfill(8))              #Server Assignment Type
        avp += self.generate_vendor_avp(624, "c0", 10415, "00000000")                               #User Data Already Available (Not Available)
        response = self.generate_diameter_packet("01", "c0", 301, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Cx Multimedia Authentication Request (MAR)
    def Request_16777216_303(self, imsi, domain):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000000")            #Vendor-Specific-Application-ID for Cx
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)
        avp += self.generate_avp(1, 40, self.string_to_hex(str(imsi) + "@" + domain))                         #User-Name
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex("sip:" + str(imsi) + "@" + domain))                      #Public-Identity
        avp += self.generate_vendor_avp(607, "c0", 10415, "00000001")                                    #3GPP-SIP-Number-Auth-Items
                                                                                                         #3GPP-SIP-Number-Auth-Data-Item
        avp += self.generate_vendor_avp(612, "c0", 10415, "00000260c000001c000028af4469676573742d414b4176312d4d4435")
        avp += self.generate_vendor_avp(602, "c0", 10415, self.ProductName)                         #Server-Name
        response = self.generate_diameter_packet("01", "c0", 303, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Cx Registration Termination Request (RTR)
    def Request_16777216_304(self, imsi, domain):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_cx'                           #Session state generate
        avp += self.generate_avp(258, 40, format(int(16777251),"x").zfill(8))                       #Auth-Application-ID Relay (#ToDo - Investigate this AVP more)
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session ID AVP
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        
        #SIP-Deregistration-Reason
        reason_code_avp = self.generate_vendor_avp(616, "c0", 10415, "00000000")
        reason_info_avp = self.generate_vendor_avp(617, "c0", 10415, self.string_to_hex("Test Reason"))
        avp += self.generate_vendor_avp(615, "c0", 10415, reason_code_avp + reason_info_avp)
        
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'hss.localdomain'),'ascii'))                 #Destination Host
        
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)
        avp += self.generate_avp(1, 40, self.string_to_hex(str(imsi) + "@" + domain))                         #User-Name
        avp += self.generate_vendor_avp(601, "c0", 10415, self.string_to_hex("sip:" + str(imsi) + "@" + domain))                      #Public-Identity
        avp += self.generate_vendor_avp(602, "c0", 10415, self.ProductName)                         #Server-Name
        #* [ Proxy-Info ]
        proxy_host_avp = self.generate_avp(280, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        proxy_state_avp = self.generate_avp(33, "40", "0001")
        avp += self.generate_avp(284, "40", proxy_host_avp + proxy_state_avp)                 #Proxy-Info  AVP ( 284 )
        
        #* [ Route-Record ]
        avp += self.generate_avp(282, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        

        response = self.generate_diameter_packet("01", "c0", 304, 16777216, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet

        return response

    #3GPP Sh User-Data Request (UDR)
    def Request_16777217_306(self, **kwargs):
        avp = ''                                                                                    #Initiate empty var AVP                                                                                           #Session-ID
        sessionid = str(self.OriginHost) + ';' + self.generate_id(5) + ';1;app_sh'                           #Session state generate
        avp += self.generate_avp(258, 40, format(int(16777251),"x").zfill(8))                       #Auth-Application-ID Relay (#ToDo - Investigate this AVP more)
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session ID AVP
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777217),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Sh)
        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm

        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'hss.localdomain'),'ascii'))                 #Destination Host
        
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)
        
        avp += self.generate_vendor_avp(602, "c0", 10415, self.ProductName)                         #Server-Name

        #* [ Route-Record ]
        avp += self.generate_avp(282, "40", str(binascii.hexlify(b'localdomain'),'ascii'))
        
        if "msisdn" in kwargs:
            msisdn = kwargs['msisdn']
            msisdn_avp = self.generate_vendor_avp(701, 'c0', 10415, self.TBCD_encode(str(msisdn)))                                             #MSISDN
            avp += self.generate_vendor_avp(700, "c0", 10415, msisdn_avp)                         #User-Identity
            avp += self.generate_vendor_avp(701, 'c0', 10415, self.TBCD_encode(str(msisdn))) 
        elif "imsi" in kwargs:
            imsi = kwargs['imsi']
            public_identity_avp = self.generate_vendor_avp(601, 'c0', 10415, self.string_to_hex(imsi))                                             #MSISDN
            avp += self.generate_vendor_avp(700, "c0", 10415, public_identity_avp)                                          #Username (IMSI)

        response = self.generate_diameter_packet("01", "c0", 306, 16777217, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet

        return response

    #3GPP S13 - ME-Identity-Check Request
    def Request_16777252_324(self, imsi, imei, software_version):
        avp = ''
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000024")           #Vendor-Specific-Application-ID for S13
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'eir.localdomain'),'ascii'))                 #Destination Host
        imei = self.generate_vendor_avp(1402, "c0", 10415, str(binascii.hexlify(str.encode(imei)),'ascii'))
        software_version = self.generate_vendor_avp(1403, "c0", 10415, self.string_to_hex(software_version))
        avp += self.generate_vendor_avp(1401, "c0", 10415, imei + software_version)                                          #Terminal Information
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        response = self.generate_diameter_packet("01", "c0", 324, 16777252, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP SLg - Provide Subscriber Location Request
    def Request_16777255_8388620(self, imsi):
        avp = ''
        #ToDo - Update the Vendor Specific Application ID
        avp += self.generate_avp(260, 40, "0000010a4000000c000028af000001024000000c01000024")           #Vendor-Specific-Application-ID for S13
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(283, 40, str(binascii.hexlify(b'localdomain'),'ascii'))                 #Destination Realm
        avp += self.generate_avp(293, 40, str(binascii.hexlify(b'mme-slg.localdomain'),'ascii'))                 #Destination Host        
        #SLg Location Type AVP
        avp += self.generate_vendor_avp(2500, "c0", 10415, "00000000")
        #Username (IMSI)
        avp += self.generate_avp(1, 40, self.string_to_hex(imsi))                                             #Username (IMSI)
        #LCS-EPS-Client-Name
        LCS_EPS_Client_Name = self.generate_vendor_avp(1238, "c0", 10415, str(binascii.hexlify(b'PyHSS GMLC'),'ascii'))    #LCS Name String
        LCS_EPS_Client_Name += self.generate_vendor_avp(1237, "c0", 10415, "00000002")     #LCS Format Indicator
        avp += self.generate_vendor_avp(2501, "c0", 10415, LCS_EPS_Client_Name)
        #LCS-Client-Type (Emergency Services)
        avp += self.generate_vendor_avp(1241, "c0", 10415, "00000000")
        response = self.generate_diameter_packet("01", "c0", 8388620, 16777255, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP SLh - Provide Subscriber Location Request
    def Request_16777291_8388622(self, **kwargs):
        avp = ''
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777291),"x").zfill(8))   #Auth-Application-ID SLh
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        sessionid = 'nickpc.localdomain;' + self.generate_id(5) + ';1;app_slh'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        
        #Username (IMSI)
        if 'imsi' in kwargs:
            avp += self.generate_avp(1, 40, self.string_to_hex(str(kwargs.get('imsi'))))                                             #Username (IMSI)
        
        #MSISDN (Optional)
        if 'msisdn' in kwargs:
            avp += self.generate_vendor_avp(701, 'c0', 10415, self.TBCD_encode(str(kwargs.get('msisdn'))))                                             #Username (IMSI)

        #GMLC Address
        avp += self.generate_vendor_avp(2405, 'c0', 10415, self.ip_to_hex('127.0.0.1'))                      #GMLC-Address

        response = self.generate_diameter_packet("01", "c0", 8388622, 16777291, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Gx - Credit Control Request
    def Request_16777238_272(self, imsi, apn, ccr_type):
        avp = ''
        sessionid = 'nickpc.localdomain;' + self.generate_id(5) + ';1;app_gx'                           #Session state generate
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.string_to_hex('ExamplePGW.com'))                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        
        avp += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx

        #CCR Type
        avp += self.generate_avp(416, 40, format(int(ccr_type),"x").zfill(8))
        avp += self.generate_avp(415, 40, format(int(0),"x").zfill(8))

        #Subscription ID
        Subscription_ID_Data = self.generate_avp(444, 40, str(binascii.hexlify(str.encode(imsi)),'ascii'))
        Subscription_ID_Type = self.generate_avp(450, 40, format(int(1),"x").zfill(8))
        avp += self.generate_avp(443, 40, Subscription_ID_Type + Subscription_ID_Data)


        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "0000000b")             #Feature-List Flags
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP

        avp += self.generate_vendor_avp(1024, 80, 10415, self.int_to_hex(1, 4))                 #Network Requests Supported
        
        avp += self.generate_avp(8, 40, '2d2d0002')                                             #Framed IP Address (ToDo - Better)
        avp += self.generate_vendor_avp(1027, 80, 10415, self.int_to_hex(5, 4))                 #IP CAN Type (EPS)
        avp += self.generate_vendor_avp(1032, 80, 10415, self.int_to_hex(1004, 4))              #RAT-Type (EUTRAN)
        #Default EPS Bearer QoS
        avp += self.generate_vendor_avp(1049, 80, 10415, 
            '0000041980000058000028af00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af00000001')
        #3GPP-User-Location-Information
        avp += self.generate_vendor_avp(22, 80, 10415, 
            '8205f539007b05f53900000001')
        avp += self.generate_vendor_avp(23, 80, 10415, '00000000')                              #MS Timezone

        #Called Station ID (APN)
        avp += self.generate_avp(30, 40, str(binascii.hexlify(str.encode(apn)),'ascii'))

        response = self.generate_diameter_packet("01", "c0", 272, 16777238, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response
