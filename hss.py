#PyHSS
#This serves as a basic 3GPP Home Subscriber Server implimenting a EIR & IMS HSS functionality
import logging
import yaml

with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

#Setup Logging
level = logging.getLevelName(yaml_config['logging']['level'])
logging.basicConfig(level=level, filename=yaml_config['logging']['logfiles']['hss_logging_file'])
if yaml_config['logging']['log_to_temrinal'] == True:
    logging.getLogger().addHandler(logging.StreamHandler())                 #Log to Stdout as well
#Loop through and create logging files if they don't exist
for logfile in yaml_config['logging']['logfiles']:
    logging.debug("Creating logfile " + str(logfile) + " at path " + str(yaml_config['logging']['logfiles'][logfile]))
    try:
        file = open(str(yaml_config['logging']['logfiles'][logfile]), 'w+')
        file.close()
    except:
        logging.error("Failed to create logfiles - Ensure you have permissions to create/write to " + str(logfile))

import sys
import socket
import socketserver
import diameter
import binascii
import time
import _thread
from threading import Thread, Lock
import os
import sctp
import traceback

logging.info("Current config file values:")
for config_sections in yaml_config:
    logging.info("\tConfig Section: " + str(config_sections))
    for lower_keys in yaml_config[config_sections]:
        logging.info("\t\t" + str(lower_keys) + "\t" + str(yaml_config[config_sections][lower_keys]))



#Initialize Diameter
diameter = diameter.Diameter(str(yaml_config['hss']['OriginHost']), str(yaml_config['hss']['OriginRealm']), str(yaml_config['hss']['ProductName']), str(yaml_config['hss']['MNC']), str(yaml_config['hss']['MCC']))

def on_new_client(clientsocket,client_address):
    logging.debug('New connection from ' + str(client_address))
    data_sum = b''
    while True:
        try:
            data = clientsocket.recv(32)
            if not data:
                logging.info("Connection closed by " + str(client_address))
                break
            
            packet_length = diameter.decode_diameter_packet_length(data)            #Calculate length of packet from start of packet
            data_sum = data + clientsocket.recv(packet_length - 32)           #Recieve remainder of packet from buffer
            packet_vars, avps = diameter.decode_diameter_packet(data_sum)   #Decode packet into array of AVPs and Dict of Packet Variables (packet_vars)

            orignHost = diameter.get_avp_data(avps, 264)[0]                         #Get OriginHost from AVP
            orignHost = binascii.unhexlify(orignHost).decode('utf-8')               #Format it


            #Send Capabilities Exchange Answer (CEA) response to Capabilites Exchange Request (CER)
            if packet_vars['command_code'] == 257 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":                    
                logging.info("Received Request with command code 257 (CER) from " + orignHost + "\n\tSending response (CEA)")
                try:
                    response = diameter.Answer_257(packet_vars, avps, str(yaml_config['hss']['bind_ip'][0]))                   #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                logging.info("Generated CER")

            #Send Credit Control Answer (CCA) response to Credit Control Request (CCR)
            elif packet_vars['command_code'] == 272 and packet_vars['ApplicationId'] == 16777238:
                logging.info("Received 3GPP Credit-Control-Request from " + orignHost + "\n\tGenerating (CCA)")
                try:
                    response = diameter.Answer_16777238_272(packet_vars, avps)          #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                logging.info("Generated CCA")

            #Send Device Watchdog Answer (DWA) response to Device Watchdog Requests (DWR)
            elif packet_vars['command_code'] == 280 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                logging.info("Received Request with command code 280 (DWR) from " + orignHost + "\n\tSending response (DWA)")
                try:
                    response = diameter.Answer_280(packet_vars, avps)                   #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                logging.info("Generated DWA")

            #Send Disconnect Peer Answer (DPA) response to Disconnect Peer Request (DPR)
            elif packet_vars['command_code'] == 282 and packet_vars['ApplicationId'] == 0 and packet_vars['flags'] == "80":
                logging.info("Received Request with command code 282 (DPR) from " + orignHost + "\n\tForwarding request...")
                response = diameter.Answer_282(packet_vars, avps)               #Generate Diameter packet
                logging.info("Generated DPA")

            #S6a Authentication Information Answer (AIA) response to Authentication Information Request (AIR)
            elif packet_vars['command_code'] == 318 and packet_vars['ApplicationId'] == 16777251 and packet_vars['flags'] == "c0":
                logging.info("Received Request with command code 318 (3GPP Authentication-Information-Request) from " + orignHost + "\n\tGenerating (AIA)")
                try:
                    response = diameter.Answer_16777251_318(packet_vars, avps)      #Generate Diameter packet
                    logging.info("Generated AIR")
                except Exception as e:
                    logging.info("Failed to generate Diameter Response for AIR")
                    logging.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                    logging.info("Generated DIAMETER_USER_DATA_NOT_AVAILABLE AIR")

            #S6a Update Location Answer (ULA) response to Update Location Request (ULR)
            elif packet_vars['command_code'] == 316 and packet_vars['ApplicationId'] == 16777251:
                logging.info("Received Request with command code 316 (3GPP Update Location-Request) from " + orignHost + "\n\tGenerating (ULA)")
                try:
                    response = diameter.Answer_16777251_316(packet_vars, avps)      #Generate Diameter packet
                    logging.info("Generated ULA")
                except Exception as e:
                    logging.info("Failed to generate Diameter Response for ULR")
                    logging.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                    logging.info("Generated error DIAMETER_USER_DATA_NOT_AVAILABLE ULA")

            #S6a Purge UE Answer (PUA) response to Purge UE Request (PUR)
            elif packet_vars['command_code'] == 321 and packet_vars['ApplicationId'] == 16777251:
                logging.info("Received Request with command code 321 (3GPP Purge UE Request) from " + orignHost + "\n\tGenerating (PUA)")
                try:
                    response = diameter.Answer_16777251_321(packet_vars, avps)      #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                    logging.error("Failed to generate PUA")
                logging.info("Generated PUA")

            #S6a Purge UE Answer (NOA) response to Notify Request (NOR)
            elif packet_vars['command_code'] == 323 and packet_vars['ApplicationId'] == 16777251:
                logging.info("Received Request with command code 323 (3GPP Notify Request) from " + orignHost + "\n\tGenerating (NOA)")
                try:
                    response = diameter.Answer_16777251_323(packet_vars, avps)      #Generate Diameter packet
                except:
                    response = diameter.Respond_ResultCode(packet_vars, avps, 5012)      #Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                    logging.error("Failed to generate NOA")
                logging.info("Generated NOA")

            #Cx Authentication Answer
            elif packet_vars['command_code'] == 300 and packet_vars['ApplicationId'] == 16777216:
                logging.info("Received Request with command code 300 (3GPP Cx User Authentication Request) from " + orignHost + "\n\tGenerating (MAA)")
                try:
                    response = diameter.Answer_16777216_300(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    logging.info("Failed to generate Diameter Response for Cx Auth Answer")
                    logging.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                logging.info("Generated Cx Auth Answer")

            #Cx Server Assignment Answer
            elif packet_vars['command_code'] == 301 and packet_vars['ApplicationId'] == 16777216:
                logging.info("Received Request with command code 301 (3GPP Cx Server Assignemnt Request) from " + orignHost + "\n\tGenerating (MAA)")
                try:
                    response = diameter.Answer_16777216_301(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    logging.info("Failed to generate Diameter Response for Cx Server Assignment Answer")
                    logging.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                logging.info("Generated Cx Server Assignment Answer")

            #Cx Location Information Answer
            elif packet_vars['command_code'] == 302 and packet_vars['ApplicationId'] == 16777216:
                logging.info("Received Request with command code 302 (3GPP Cx Location Information Request) from " + orignHost + "\n\tGenerating (MAA)")
                try:
                    response = diameter.Answer_16777216_302(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    logging.info("Failed to generate Diameter Response for Cx Location Information Answer")
                    logging.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                logging.info("Generated Cx Location Information Answer")

            #Cx Multimedia Authentication Answer
            elif packet_vars['command_code'] == 303 and packet_vars['ApplicationId'] == 16777216:
                logging.info("Received Request with command code 303 (3GPP Cx Multimedia Authentication Request) from " + orignHost + "\n\tGenerating (MAA)")
                try:
                    response = diameter.Answer_16777216_303(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    logging.info("Failed to generate Diameter Response for Cx Multimedia Authentication Answer")
                    logging.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                logging.info("Generated Cx Multimedia Authentication Answer")

            #S13 ME-Identity-Check Answer
            elif packet_vars['command_code'] == 324 and packet_vars['ApplicationId'] == 16777252:
                logging.info("Received Request with command code 324 (3GPP S13 ME-Identity-Check Request) from " + orignHost + "\n\tGenerating (MICA)")
                try:
                    response = diameter.Answer_16777252_324(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    logging.info("Failed to generate Diameter Response for S13 ME-Identity Check Answer")
                    logging.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                logging.info("Generated S13 ME-Identity Check Answer")

            #SLh LCS-Routing-Info-Answer
            elif packet_vars['command_code'] == 8388622 and packet_vars['ApplicationId'] == 16777291:
                logging.info("Received Request with command code 324 (3GPP SLh LCS-Routing-Info-Answer Request) from " + orignHost + "\n\tGenerating (MICA)")
                try:
                    response = diameter.Answer_16777291_8388622(packet_vars, avps)      #Generate Diameter packet
                except Exception as e:
                    logging.info("Failed to generate Diameter Response for SLh LCS-Routing-Info-Answer")
                    logging.info(e)
                    traceback.print_exc()
                    response = diameter.Respond_ResultCode(packet_vars, avps, 4100) #DIAMETER_USER_DATA_NOT_AVAILABLE
                logging.info("Generated SLh LCS-Routing-Info-Answer")

            else:
                logging.error("\n\nRecieved unrecognised request with Command Code: " + str(packet_vars['command_code']) + ", ApplicationID: " + str(packet_vars['ApplicationId']) + " and flags " + str(packet_vars['flags']))
                for keys in packet_vars:
                    logging.error(keys)
                    logging.error("\t" + str(packet_vars[keys]))
                logging.error(avps)
                logging.error("Sending negative response")
                response = diameter.Respond_ResultCode(packet_vars, avps, 3001)      #Generate Diameter response with "Command Unsupported" (3001)
                clientsocket.sendall(bytes.fromhex(response))                           #Send it

            #Handle actual sending
            try:
                clientsocket.sendall(bytes.fromhex(response))                           #Send it
            except Exception as e:
                    logging.info("Failed to send Diameter Response")
                    logging.debug("Diameter Response Body: " + str(response))
                    logging.info(e)
                    traceback.print_exc()

                    
        except KeyboardInterrupt:
            #Clean up the connection on keyboard interupt
            response = diameter.Request_282()                       #Generate Disconnect Peer Request Diameter packet
            clientsocket.sendall(bytes.fromhex(response))             #Send it
            clientsocket.close()
            logging.info("Connection closed niceley due to keyboard interrupt")
            sys.exit()
    

if yaml_config['hss']['transport'] == "SCTP":
    logging.debug("Using SCTP for Transport")
    # Create a SCTP socket
    sock = sctp.sctpsocket_tcp(socket.AF_INET)
    # Loop through the possible Binding IPs from the config and bind to each for Multihoming
    server_addresses = []
    for host in yaml_config['hss']['bind_ip']:
        logging.info("Seting up SCTP binding on local IP address " + str(host))
        server_addresses.append((str(host), int(yaml_config['hss']['bind_port'])))
    sock.bindx(server_addresses)
    logging.info("PyHSS listening on SCTP port " + str(server_addresses))
    # Listen for up to 5 incoming connection
    sock.listen(5)
elif yaml_config['hss']['transport'] == "TCP":
    logging.debug("Using TCP socket")
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    server_address = (str(yaml_config['hss']['bind_ip'][0]), int(yaml_config['hss']['bind_port']))    
    sock.bind(server_address)
    logging.debug('PyHSS listening on TCP port ' + str(yaml_config['hss']['bind_ip'][0]))
    # Listen for up to 1 incoming connection
    sock.listen(5)
else:
    logging.error("No valid transports found (No SCTP or TCP) - Exiting")
    sys.exit()

while True:
    # Wait for a connection
    logging.info('Waiting for a connection...')
    connection, client_address = sock.accept()
    _thread.start_new_thread(on_new_client,(connection,client_address))
    

