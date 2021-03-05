#PyHSS
#This serves as a basic 3GPP Home Subscriber Server implimenting a EIR & IMS HSS functionality
import logging
import yaml

with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

#Setup Logging
level = logging.getLevelName(yaml_config['logging']['level'])
logging.basicConfig(level=level)

import sys
import socket
import socketserver
import diameter
import binascii
import time
from threading import Thread, Lock
import os

logging.info("Current config file values:")
for config_sections in yaml_config:
    logging.info("\tConfig Section: " + str(config_sections))
    for lower_keys in yaml_config[config_sections]:
        logging.info("\t\t" + str(lower_keys) + "\t" + str(yaml_config[config_sections][lower_keys]))






#Initialize Diameter
diameter = diameter.Diameter(str(yaml_config['hss']['OriginHost']), str(yaml_config['hss']['OriginRealm']), str(yaml_config['hss']['ProductName']), str(yaml_config['hss']['MNC']), str(yaml_config['hss']['MCC']))


class DiameterRequestHandler(socketserver.BaseRequestHandler):
    print('PyHSS started - listening on ' + str(yaml_config['hss']['bind_ip'][0]) + ' port ' + str(yaml_config['hss']['bind_port']))
    data_sum = b''
    firstloop = 0
    def setup(self):
        print('New connection from ' + str(self.client_address[0]))
        while 1:

            data = self.request.recv(32)
            if not data:
                print("Connection closed by " + str(self.client_address[0]))
                break
            try:            
                packet_length = diameter.decode_diameter_packet_length(data)            #Calculate length of packet from start of packet
                data_sum = data + self.request.recv(packet_length - 32)                 #Recieve remainder of packet from buffer
                packet_vars, avps = diameter.decode_diameter_packet(data_sum)           #Decode packet into array of AVPs and Dict of Packet Variables (packet_vars)

                orignHost = diameter.get_avp_data(avps, 264)[0]                         #Get OriginHost from AVP
                orignHost = binascii.unhexlify(orignHost).decode('utf-8')               #Format it
            except:
                logging.info("Failed to get packet_vars and AVPs from " + str(self.client_address[0]))

                

            #Send Capabilities Exchange Answer (CEA) response to Capabilites Exchange Request (CER)
            if packet_vars['command_code'] == 257 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":                    
                print("Received Request with command code 257 (CER) from " + orignHost + "\n\tSending response (CEA)")
                response = diameter.Answer_257(packet_vars, avps, str(yaml_config['hss']['bind_ip'][0]))                   #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                       #Send it


            #Send Credit Control Answer (CCA) response to Credit Control Request (CCR)
            elif packet_vars['command_code'] == 272 and packet_vars['ApplicationId'] == 16777238:
                print("Received 3GPP Credit-Control-Request from " + orignHost + "\n\tGenerating (CCA)")
                response = diameter.Answer_16777238_272(packet_vars, avps)          #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                       #Send it


            #Send Device Watchdog Answer (DWA) response to Device Watchdog Requests (DWR)
            elif packet_vars['command_code'] == 280 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                #print("Received Request with command code 280 (DWR) from " + orignHost + "\n\tSending response (DWA)")
                response = diameter.Answer_280(packet_vars, avps)                   #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                       #Send it


            #Send Disconnect Peer Answer (DPA) response to Disconnect Peer Request (DPR)
            elif packet_vars['command_code'] == 282 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                print("Received Request with command code 282 (DPR) from " + orignHost + "\n\tForwarding request...")
                response = diameter.Answer_282(packet_vars, avps)               #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it


            #S6a Authentication Information Answer (AIA) response to Authentication Information Request (AIR)
            elif packet_vars['command_code'] == 318 and packet_vars['ApplicationId'] == 16777251 and packet_vars['flags'] == "c0":
                print("Received Request with command code 318 (3GPP Authentication-Information-Request) from " + orignHost + "\n\tGenerating (AIA)")
                response = diameter.Answer_16777251_318(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it

            #S6a Update Location Answer (ULA) response to Update Location Request (ULR)
            elif packet_vars['command_code'] == 316 and packet_vars['ApplicationId'] == 16777251:
                print("Received Request with command code 316 (3GPP Update Location-Request) from " + orignHost + "\n\tGenerating (ULA)")
                response = diameter.Answer_16777251_316(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it


            #S6a Purge UE Answer (PUA) response to Purge UE Request (PUR)
            elif packet_vars['command_code'] == 321 and packet_vars['ApplicationId'] == 16777251:
                print("Received Request with command code 321 (3GPP Purge UE Request) from " + orignHost + "\n\tGenerating (PUA)")
                response = diameter.Answer_16777251_321(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it

            #S6a Purge UE Answer (NOA) response to Notify Request (NOR)
            elif packet_vars['command_code'] == 323 and packet_vars['ApplicationId'] == 16777251:
                print("Received Request with command code 323 (3GPP Notify Request) from " + orignHost + "\n\tGenerating (NOA)")
                response = diameter.Answer_16777251_323(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it


            #Cx Authentication Answer
            elif packet_vars['command_code'] == 300 and packet_vars['ApplicationId'] == 16777216:
                print("Received Request with command code 300 (3GPP Cx User Authentication Request) from " + orignHost + "\n\tGenerating (MAA)")
                response = diameter.Answer_16777216_300(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it

            #Cx Server Assignment Answer
            elif packet_vars['command_code'] == 301 and packet_vars['ApplicationId'] == 16777216:
                print("Received Request with command code 301 (3GPP Cx Server Assignemnt Request) from " + orignHost + "\n\tGenerating (MAA)")
                response = diameter.Answer_16777216_301(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it

            #Cx Location Information Answer
            elif packet_vars['command_code'] == 302 and packet_vars['ApplicationId'] == 16777216:
                print("Received Request with command code 302 (3GPP Cx Location Information Request) from " + orignHost + "\n\tGenerating (MAA)")
                response = diameter.Answer_16777216_302(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it

            #Cx Multimedia Authentication Answer
            elif packet_vars['command_code'] == 303 and packet_vars['ApplicationId'] == 16777216:
                print("Received Request with command code 303 (3GPP Cx Multimedia Authentication Request) from " + orignHost + "\n\tGenerating (MAA)")
                response = diameter.Answer_16777216_303(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                   #Send it

            #S13 ME-Identity-Check Answer
            elif packet_vars['command_code'] == 324 and packet_vars['ApplicationId'] == 16777252:
                print("Received Request with command code 324 (3GPP S13 ME-Identity-Check Request) from " + orignHost + "\n\tGenerating (MICA)")
                response = diameter.Answer_16777252_324(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))   

            #SLh LCS-Routing-Info-Answer
            elif packet_vars['command_code'] == 8388622 and packet_vars['ApplicationId'] == 16777291:
                print("Received Request with command code 324 (3GPP SLh LCS-Routing-Info-Answer Request) from " + orignHost + "\n\tGenerating (MICA)")
                response = diameter.Answer_16777291_8388622(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))   


            else:
                print("\n\nRecieved unrecognised request with Command Code: " + str(packet_vars['command_code']) + ", ApplicationID: " + str(packet_vars['ApplicationId']) + " and flags " + str(packet_vars['flags']))
                for keys in packet_vars:
                    print(keys)
                    print("\t" + str(packet_vars[keys]))
                print(avps)
                print("Sending negative response")
                packet_vars, avps
                response = diameter.Respond_Command_Unsupported(packet_vars, avps)      #Generate Diameter packet
                self.request.sendall(bytes.fromhex(response))                           #Send it




server = socketserver.ThreadingTCPServer((str(yaml_config['hss']['bind_ip'][0]), int(yaml_config['hss']['bind_port'])), DiameterRequestHandler)

server.serve_forever()
