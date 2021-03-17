#PyHSS
#This serves as a basic 3GPP Home Subscriber Server implimenting a EIR & IMS HSS functionality
import logging
import yaml

with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

import os
import sys
sys.path.append(os.path.realpath('lib'))

#Setup Logging
import logtool
logtool.setup_logger('HSS_Logger', yaml_config['logging']['logfiles']['hss_logging_file'], level=yaml_config['logging']['level'])
HSS_Logger = logging.getLogger('HSS_Logger')

if yaml_config['logging']['log_to_terminal'] == True:
    logging.getLogger().addHandler(logging.StreamHandler())                 #Log to Stdout as well

import socket
import socketserver
import diameter
import binascii
import time
import _thread
from threading import Thread, Lock
import sctp
import traceback

HSS_Logger.info("Current config file values:")
for config_sections in yaml_config:
    HSS_Logger.info("\tConfig Section: " + str(config_sections))
    for lower_keys in yaml_config[config_sections]:
        HSS_Logger.info("\t\t" + str(lower_keys) + "\t" + str(yaml_config[config_sections][lower_keys]))



#Initialize Diameter
diameter = diameter.Diameter(str(yaml_config['hss']['OriginHost']), str(yaml_config['hss']['OriginRealm']), str(yaml_config['hss']['ProductName']), str(yaml_config['hss']['MNC']), str(yaml_config['hss']['MCC']))

def on_new_client(clientsocket,client_address):
    HSS_Logger.debug('New connection from ' + str(client_address))
    data_sum = b''
    while True:
        try:
            data = clientsocket.recv(32)
            if not data:
                HSS_Logger.info("Connection closed by " + str(client_address))
                break
            
            packet_length = diameter.decode_diameter_packet_length(data)            #Calculate length of packet from start of packet
            data_sum = data + clientsocket.recv(packet_length - 32)           #Recieve remainder of packet from buffer
            packet_vars, avps = diameter.decode_diameter_packet(data_sum)   #Decode packet into array of AVPs and Dict of Packet Variables (packet_vars)

            orignHost = diameter.get_avp_data(avps, 264)[0]                         #Get OriginHost from AVP
            orignHost = binascii.unhexlify(orignHost).decode('utf-8')               #Format it


            #Send Capabilities Exchange Answer (CEA) response to Capabilites Exchange Request (CER)
            if packet_vars['command_code'] == 257 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":                    
                HSS_Logger.info("Received Request with command code 257 (CER) from " + orignHost + "\n\tSending response (CEA)")
                try:
                    response = diameter.Answer_257(packet_vars, avps, str(yaml_config['hss']['bind_ip'][0]))                   #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                HSS_Logger.info("Generated CER")

            #Send Credit Control Answer (CCA) response to Credit Control Request (CCR)
            elif packet_vars['command_code'] == 272 and packet_vars['ApplicationId'] == 16777238:
                HSS_Logger.info("Received 3GPP Credit-Control-Request from " + orignHost + "\n\tGenerating (CCA)")
                try:
                    response = diameter.Answer_16777238_272(packet_vars, avps)          #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                HSS_Logger.info("Generated CCA")

            #Send Device Watchdog Answer (DWA) response to Device Watchdog Requests (DWR)
            elif packet_vars['command_code'] == 280 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                HSS_Logger.info("Received Request with command code 280 (DWR) from " + orignHost + "\n\tSending response (DWA)")
                try:
                    response = diameter.Answer_280(packet_vars, avps)                   #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                HSS_Logger.info("Generated DWA")

            #Send Disconnect Peer Answer (DPA) response to Disconnect Peer Request (DPR)
            elif packet_vars['command_code'] == 282 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                HSS_Logger.info("Received Request with command code 282 (DPR) from " + orignHost + "\n\tForwarding request...")
                response = diameter.Answer_282(packet_vars, avps)               #Generate Diameter packet
                HSS_Logger.info("Generated DPA")

            #S6a Authentication Information Answer (AIA) response to Authentication Information Request (AIR)
            elif packet_vars['command_code'] == 318 and packet_vars['ApplicationId'] == 16777251 and packet_vars['flags'] == "c0":
                HSS_Logger.info("Received Request with command code 318 (3GPP Authentication-Information-Request) from " + orignHost + "\n\tGenerating (AIA)")
                try:
                    response = diameter.Answer_16777251_318(packet_vars, avps)      #Generate Diameter packet
                    HSS_Logger.info("Generated AIR")
                except Exception as e:
                    HSS_Logger.info("Failed to generate Diameter Response for AIR")
                    HSS_Logger.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                    HSS_Logger.info("Generated DIAMETER_USER_DATA_NOT_AVAILABLE AIR")

            #S6a Update Location Answer (ULA) response to Update Location Request (ULR)
            elif packet_vars['command_code'] == 316 and packet_vars['ApplicationId'] == 16777251:
                HSS_Logger.info("Received Request with command code 316 (3GPP Update Location-Request) from " + orignHost + "\n\tGenerating (ULA)")
                try:
                    response = diameter.Answer_16777251_316(packet_vars, avps)      #Generate Diameter packet
                    HSS_Logger.info("Generated ULA")
                except Exception as e:
                    HSS_Logger.info("Failed to generate Diameter Response for ULR")
                    HSS_Logger.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                    HSS_Logger.info("Generated error DIAMETER_USER_DATA_NOT_AVAILABLE ULA")

            #S6a Purge UE Answer (PUA) response to Purge UE Request (PUR)
            elif packet_vars['command_code'] == 321 and packet_vars['ApplicationId'] == 16777251:
                HSS_Logger.info("Received Request with command code 321 (3GPP Purge UE Request) from " + orignHost + "\n\tGenerating (PUA)")
                try:
                    response = diameter.Answer_16777251_321(packet_vars, avps)      #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                    HSS_Logger.error("Failed to generate PUA")
                HSS_Logger.info("Generated PUA")

            #S6a Purge UE Answer (NOA) response to Notify Request (NOR)
            elif packet_vars['command_code'] == 323 and packet_vars['ApplicationId'] == 16777251:
                HSS_Logger.info("Received Request with command code 323 (3GPP Notify Request) from " + orignHost + "\n\tGenerating (NOA)")
                try:
                    response = diameter.Answer_16777251_323(packet_vars, avps)      #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                    HSS_Logger.error("Failed to generate NOA")
                HSS_Logger.info("Generated NOA")

            #Cx Authentication Answer
            elif packet_vars['command_code'] == 300 and packet_vars['ApplicationId'] == 16777216:
                HSS_Logger.info("Received Request with command code 300 (3GPP Cx User Authentication Request) from " + orignHost + "\n\tGenerating (MAA)")
                try:
                    response = diameter.Answer_16777216_300(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    HSS_Logger.info("Failed to generate Diameter Response for Cx Auth Answer")
                    HSS_Logger.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                HSS_Logger.info("Generated Cx Auth Answer")

            #Cx Server Assignment Answer
            elif packet_vars['command_code'] == 301 and packet_vars['ApplicationId'] == 16777216:
                HSS_Logger.info("Received Request with command code 301 (3GPP Cx Server Assignemnt Request) from " + orignHost + "\n\tGenerating (MAA)")
                try:
                    response = diameter.Answer_16777216_301(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    HSS_Logger.info("Failed to generate Diameter Response for Cx Server Assignment Answer")
                    HSS_Logger.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                HSS_Logger.info("Generated Cx Server Assignment Answer")

            #Cx Location Information Answer
            elif packet_vars['command_code'] == 302 and packet_vars['ApplicationId'] == 16777216:
                HSS_Logger.info("Received Request with command code 302 (3GPP Cx Location Information Request) from " + orignHost + "\n\tGenerating (MAA)")
                try:
                    response = diameter.Answer_16777216_302(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    HSS_Logger.info("Failed to generate Diameter Response for Cx Location Information Answer")
                    HSS_Logger.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                HSS_Logger.info("Generated Cx Location Information Answer")

            #Cx Multimedia Authentication Answer
            elif packet_vars['command_code'] == 303 and packet_vars['ApplicationId'] == 16777216:
                HSS_Logger.info("Received Request with command code 303 (3GPP Cx Multimedia Authentication Request) from " + orignHost + "\n\tGenerating (MAA)")
                try:
                    response = diameter.Answer_16777216_303(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    HSS_Logger.info("Failed to generate Diameter Response for Cx Multimedia Authentication Answer")
                    HSS_Logger.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                HSS_Logger.info("Generated Cx Multimedia Authentication Answer")

            #S13 ME-Identity-Check Answer
            elif packet_vars['command_code'] == 324 and packet_vars['ApplicationId'] == 16777252:
                HSS_Logger.info("Received Request with command code 324 (3GPP S13 ME-Identity-Check Request) from " + orignHost + "\n\tGenerating (MICA)")
                try:
                    response = diameter.Answer_16777252_324(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    HSS_Logger.info("Failed to generate Diameter Response for S13 ME-Identity Check Answer")
                    HSS_Logger.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                HSS_Logger.info("Generated S13 ME-Identity Check Answer")

            #SLh LCS-Routing-Info-Answer
            elif packet_vars['command_code'] == 8388622 and packet_vars['ApplicationId'] == 16777291:
                HSS_Logger.info("Received Request with command code 324 (3GPP SLh LCS-Routing-Info-Answer Request) from " + orignHost + "\n\tGenerating (MICA)")
                try:
                    response = diameter.Answer_16777291_8388622(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    HSS_Logger.info("Failed to generate Diameter Response for SLh LCS-Routing-Info-Answer")
                    HSS_Logger.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                HSS_Logger.info("Generated SLh LCS-Routing-Info-Answer")

            else:
                HSS_Logger.error("\n\nRecieved unrecognised request with Command Code: " + str(packet_vars['command_code']) + ", ApplicationID: " + str(packet_vars['ApplicationId']) + " and flags " + str(packet_vars['flags']))
                for keys in packet_vars:
                    HSS_Logger.error(keys)
                    HSS_Logger.error("\t" + str(packet_vars[keys]))
                HSS_Logger.error(avps)
                HSS_Logger.error("Sending negative response")
                response = diameter.Respond_ResultCode(packet_vars, avps, 3001)      #Generate Diameter response with "Command Unsupported" (3001)
                clientsocket.sendall(bytes.fromhex(response))                           #Send it

            #Handle actual sending
            try:
                clientsocket.sendall(bytes.fromhex(response))                           #Send it
            except Exception as e:
                    HSS_Logger.info("Failed to send Diameter Response")
                    HSS_Logger.debug("Diameter Response Body: " + str(response))
                    HSS_Logger.info(e)
                    traceback.print_exc()

                    
        except KeyboardInterrupt:
            #Clean up the connection on keyboard interupt
            response = diameter.Request_282()                       #Generate Disconnect Peer Request Diameter packet
            clientsocket.sendall(bytes.fromhex(response))             #Send it
            clientsocket.close()
            HSS_Logger.info("Connection closed niceley due to keyboard interrupt")
            sys.exit()
    

if yaml_config['hss']['transport'] == "SCTP":
    HSS_Logger.debug("Using SCTP for Transport")
    # Create a SCTP socket
    sock = sctp.sctpsocket_tcp(socket.AF_INET)
    # Loop through the possible Binding IPs from the config and bind to each for Multihoming
    server_addresses = []
    for host in yaml_config['hss']['bind_ip']:
        HSS_Logger.info("Seting up SCTP binding on local IP address " + str(host))
        server_addresses.append((str(host), int(yaml_config['hss']['bind_port'])))
    sock.bindx(server_addresses)
    HSS_Logger.info("PyHSS listening on SCTP port " + str(server_addresses))
    # Listen for up to 5 incoming connection
    sock.listen(5)
elif yaml_config['hss']['transport'] == "TCP":
    HSS_Logger.debug("Using TCP socket")
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    server_address = (str(yaml_config['hss']['bind_ip'][0]), int(yaml_config['hss']['bind_port']))    
    sock.bind(server_address)
    HSS_Logger.debug('PyHSS listening on TCP port ' + str(yaml_config['hss']['bind_ip'][0]))
    # Listen for up to 1 incoming connection
    sock.listen(5)
else:
    HSS_Logger.error("No valid transports found (No SCTP or TCP) - Exiting")
    sys.exit()

while True:
    # Wait for a connection
    HSS_Logger.info('Waiting for a connection...')
    connection, client_address = sock.accept()
    _thread.start_new_thread(on_new_client,(connection,client_address))
    

