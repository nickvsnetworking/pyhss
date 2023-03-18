# PyHSS
# This serves as a basic 3GPP Home Subscriber Server implimenting a EIR & IMS HSS functionality
import logging
import yaml
import os
import sys
import socket
import socketserver
import binascii
import time
import _thread
import threading
import sctp
import traceback
import pprint
import diameter as DiameterLib
import systemd.daemon
from threading import Thread, Lock
from logtool import *


class PyHSS:
    def __init__(self):
        # Load config from yaml file
        with open("config.yaml", "r") as config_stream:
            self.yaml_config = yaml.safe_load(config_stream)

        # Setup logging
        self.logtool = LogTool(HSS_Init=True)
        self.logtool.setup_logger(
            "HSS_Logger",
            self.yaml_config["logging"]["logfiles"]["hss_logging_file"],
            level=self.yaml_config["logging"]["level"],
        )
        self.logger = logging.getLogger("HSS_Logger")
        if self.yaml_config["logging"]["log_to_terminal"]:
            logging.getLogger().addHandler(logging.StreamHandler())

        # Setup Diameter
        self.diameter_instance = DiameterLib.Diameter(
            str(self.yaml_config["hss"].get("OriginHost", "")),
            str(self.yaml_config["hss"].get("OriginRealm", "")),
            str(self.yaml_config["hss"].get("ProductName", "")),
            str(self.yaml_config["hss"].get("MNC", "")),
            str(self.yaml_config["hss"].get("MCC", "")),
        )

    def handle_new_connection(self, clientsocket, client_address):
        # Create an event to signal when the client socket is closed
        self.socket_close_event = threading.Event()
        self.logger.debug(f"New connection from {client_address}")
        self.logtool.Manage_Diameter_Peer(client_address, client_address, "add")
        manage_client_thread = threading.Thread(
            target=self.manage_client,
            args=(
                clientsocket,
                client_address,
                self.diameter_instance,
                self.socket_close_event,
            ),
        )
        self.logger.debug("Main: before manage_client thread")
        manage_client_thread.start()

        # If Redis is enabled, start manage_client_async and manage_client_dwr threads.
        if self.yaml_config["redis"]["enabled"]:
            if "async_check_interval" not in self.yaml_config["hss"] or self.yaml_config["hss"]["async_check_interval"] == 0:
                self.yaml_config["hss"]["async_check_interval"] = 10
            manage_client_async_thread = threading.Thread(
                target=self.manage_client_async,
                args=(
                    clientsocket,
                    client_address,
                    self.diameter_instance,
                    self.socket_close_event,
                ),
            )
            self.logger.debug("Main: before manage_client_async thread")
            manage_client_async_thread.start()

            manage_client_dwr_thread = threading.Thread(
                target=self.manage_client_dwr,
                args=(
                    clientsocket,
                    client_address,
                    self.diameter_instance,
                    self.socket_close_event,
                ),
            )
            self.logger.debug("Main: before manage_client_dwr thread")
            manage_client_dwr_thread.start()

        self.logger.debug(
            f"handle_new_connection: Total PyHSS Active Threads: {threading.active_count()}"
        )

        # Wait for the signal to close all threads
        self.socket_close_event.wait()
        self.logger.debug(f"Closing thread for client; {client_address}")
        return

    @prom_diam_response_time_diam.time()
    def process_Diameter_request(self, clientsocket, client_address, diameter, data):
        packet_length = diameter.decode_diameter_packet_length(
            data
        )  # Calculate length of packet from start of packet
        data_sum = data + clientsocket.recv(
            packet_length - 32
        )  # Recieve remainder of packet from buffer
        packet_vars, avps = diameter.decode_diameter_packet(
            data_sum
        )  # Decode packet into array of AVPs and Dict of Packet Variables (packet_vars)
        try:
            packet_vars["Source_IP"] = client_address[0]
        except:
            self.logger.debug("Failed to add Source_IP to packet_vars")

        start_time = time.time()
        origin_host = diameter.get_avp_data(avps, 264)[0]  # Get OriginHost from AVP
        origin_host = binascii.unhexlify(origin_host).decode("utf-8")  # Format it

        # label_values = str(packet_vars['ApplicationId']), str(packet_vars['command_code']), origin_host, 'request'
        prom_diam_request_count.labels(
            str(packet_vars["ApplicationId"]),
            str(packet_vars["command_code"]),
            origin_host,
            "request",
        ).inc()

        # Gobble up any Response traffic that is sent to us:
        if packet_vars["flags_bin"][0:1] == "0":
            self.logger.info("Got a Response, not a request - dropping it.")
            self.logger.info(packet_vars)
            return

        # Send Capabilities Exchange Answer (CEA) response to Capabilites Exchange Request (CER)
        elif (
            packet_vars["command_code"] == 257
            and packet_vars["ApplicationId"] == 0
            and packet_vars["flags"] == "80"
        ):
            self.logger.info(
                f"Received Request with command code 257 (CER) from {origin_host}"
                + "\n\tSending response (CEA)"
            )
            try:
                response = diameter.Answer_257(
                    packet_vars, avps, str(self.yaml_config["hss"]["bind_ip"][0])
                )  # Generate Diameter packet
                # prom_diam_response_count_successful.inc()
            except:
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 5012
                )  # Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                # prom_diam_response_count_fail.inc()
            self.logger.info("Generated CEA")
            self.logtool.Manage_Diameter_Peer(origin_host, client_address, "update")
            prom_diam_connected_peers.labels(origin_host).set(1)

        # Send Credit Control Answer (CCA) response to Credit Control Request (CCR)
        elif (
            packet_vars["command_code"] == 272
            and packet_vars["ApplicationId"] == 16777238
        ):
            self.logger.info(
                f"Received 3GPP Credit-Control-Request from {origin_host}"
                + "\n\tGenerating (CCA)"
            )
            try:
                response = diameter.Answer_16777238_272(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as E:
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 5012
                )  # Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                self.logger.error(f"Failed to generate response {str(E)}")
            self.logger.info("Generated CCA")

        # Send Device Watchdog Answer (DWA) response to Device Watchdog Requests (DWR)
        elif (
            packet_vars["command_code"] == 280
            and packet_vars["ApplicationId"] == 0
            and packet_vars["flags"] == "80"
        ):
            self.logger.info(
                f"Received Request with command code 280 (DWR) from {origin_host}"
                + "\n\tSending response (DWA)"
            )
            try:
                response = diameter.Answer_280(
                    packet_vars, avps
                )  # Generate Diameter packet
            except:
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 5012
                )  # Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
            self.logger.info("Generated DWA")
            self.logtool.Manage_Diameter_Peer(origin_host, client_address, "update")

        # Send Disconnect Peer Answer (DPA) response to Disconnect Peer Request (DPR)
        elif (
            packet_vars["command_code"] == 282
            and packet_vars["ApplicationId"] == 0
            and packet_vars["flags"] == "80"
        ):
            self.logger.info(
                f"Received Request with command code 282 (DPR) from {origin_host}"
                + "\n\tForwarding request..."
            )
            response = diameter.Answer_282(
                packet_vars, avps
            )  # Generate Diameter packet
            self.logger.info("Generated DPA")
            self.logtool.Manage_Diameter_Peer(origin_host, client_address, "remove")
            prom_diam_connected_peers.labels(origin_host).set(0)

        # S6a Authentication Information Answer (AIA) response to Authentication Information Request (AIR)
        elif (
            packet_vars["command_code"] == 318
            and packet_vars["ApplicationId"] == 16777251
            and packet_vars["flags"] == "c0"
        ):
            self.logger.info(
                f"Received Request with command code 318 (3GPP Authentication-Information-Request) from {origin_host}"
                + "\n\tGenerating (AIA)"
            )
            try:
                response = diameter.Answer_16777251_318(
                    packet_vars, avps
                )  # Generate Diameter packet
                self.logger.info("Generated AIR")
            except Exception as e:
                self.logger.info("Failed to generate Diameter Response for AIR")
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 4100
                )  # DIAMETER_USER_DATA_NOT_AVAILABLE
                self.logger.info("Generated DIAMETER_USER_DATA_NOT_AVAILABLE AIR")

        # S6a Update Location Answer (ULA) response to Update Location Request (ULR)
        elif (
            packet_vars["command_code"] == 316
            and packet_vars["ApplicationId"] == 16777251
        ):
            self.logger.info(
                f"Received Request with command code 316 (3GPP Update Location-Request) from {origin_host}"
                + "\n\tGenerating (ULA)"
            )
            try:
                response = diameter.Answer_16777251_316(
                    packet_vars, avps
                )  # Generate Diameter packet
                self.logger.info("Generated ULA")
            except Exception as e:
                self.logger.info("Failed to generate Diameter Response for ULR")
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 4100
                )  # DIAMETER_USER_DATA_NOT_AVAILABLE
                self.logger.info("Generated error DIAMETER_USER_DATA_NOT_AVAILABLE ULA")

            # Send ULA data & clear tx buffer
            clientsocket.sendall(bytes.fromhex(response))
            response = ""
            if "Insert_Subscriber_Data_Force" in yaml_config["hss"]:
                if yaml_config["hss"]["Insert_Subscriber_Data_Force"] == True:
                    self.logger.debug("ISD triggered after ULA")
                    # Generate Insert Subscriber Data Request
                    response = diameter.Request_16777251_319(
                        packet_vars, avps
                    )  # Generate Diameter packet
                    self.logger.info("Generated IDR")
                    # Send ISD data
                    clientsocket.sendall(bytes.fromhex(response))
                    self.logger.info("Sent IDR")
            return
        # S6a inbound Insert-Data-Answer in response to our IDR
        elif (
            packet_vars["command_code"] == 319
            and packet_vars["ApplicationId"] == 16777251
        ):
            self.logger.info(
                f"Received response with command code 319 (3GPP Insert-Subscriber-Answer) from {origin_host}"
            )
            return
        # S6a Purge UE Answer (PUA) response to Purge UE Request (PUR)
        elif (
            packet_vars["command_code"] == 321
            and packet_vars["ApplicationId"] == 16777251
        ):
            self.logger.info(
                f"Received Request with command code 321 (3GPP Purge UE Request) from {origin_host}"
                + "\n\tGenerating (PUA)"
            )
            try:
                response = diameter.Answer_16777251_321(
                    packet_vars, avps
                )  # Generate Diameter packet
            except:
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 5012
                )  # Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                self.logger.error("Failed to generate PUA")
            self.logger.info("Generated PUA")
        # S6a Notify Answer (NOA) response to Notify Request (NOR)
        elif (
            packet_vars["command_code"] == 323
            and packet_vars["ApplicationId"] == 16777251
        ):
            self.logger.info(
                f"Received Request with command code 323 (3GPP Notify Request) from {origin_host}"
                + "\n\tGenerating (NOA)"
            )
            try:
                response = diameter.Answer_16777251_323(
                    packet_vars, avps
                )  # Generate Diameter packet
            except:
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 5012
                )  # Generate Diameter response with "DIAMETER_UNABLE_TO_COMPLY" (5012)
                self.logger.error("Failed to generate NOA")
            self.logger.info("Generated NOA")
        # S6a Cancel Location Answer eater
        elif (
            packet_vars["command_code"] == 317
            and packet_vars["ApplicationId"] == 16777251
        ):
            self.logger.info(
                f"Received Request with command code 317 (3GPP Cancel Location Request) from {origin_host}"
                + "\n\tDoing nothing"
            )

        # Cx Authentication Answer
        elif (
            packet_vars["command_code"] == 300
            and packet_vars["ApplicationId"] == 16777216
        ):
            self.logger.info(
                f"Received Request with command code 300 (3GPP Cx User Authentication Request) from {origin_host}"
                + "\n\tGenerating (MAA)"
            )
            try:
                response = diameter.Answer_16777216_300(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as e:
                self.logger.info(
                    "Failed to generate Diameter Response for Cx Auth Answer"
                )
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 4100
                )  # DIAMETER_USER_DATA_NOT_AVAILABLE
            self.logger.info("Generated Cx Auth Answer")

        # Cx Server Assignment Answer
        elif (
            packet_vars["command_code"] == 301
            and packet_vars["ApplicationId"] == 16777216
        ):
            self.logger.info(
                f"Received Request with command code 301 (3GPP Cx Server Assignemnt Request) from {origin_host}"
                + "\n\tGenerating (MAA)"
            )
            try:
                response = diameter.Answer_16777216_301(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as e:
                self.logger.info(
                    "Failed to generate Diameter Response for Cx Server Assignment Answer"
                )
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 4100
                )  # DIAMETER_USER_DATA_NOT_AVAILABLE
            self.logger.info("Generated Cx Server Assignment Answer")

        # Cx Location Information Answer
        elif (
            packet_vars["command_code"] == 302
            and packet_vars["ApplicationId"] == 16777216
        ):
            self.logger.info(
                f"Received Request with command code 302 (3GPP Cx Location Information Request) from {origin_host}"
                + "\n\tGenerating (MAA)"
            )
            try:
                response = diameter.Answer_16777216_302(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as e:
                self.logger.info(
                    "Failed to generate Diameter Response for Cx Location Information Answer"
                )
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 4100
                )  # DIAMETER_USER_DATA_NOT_AVAILABLE
            self.logger.info("Generated Cx Location Information Answer")

        # Cx Multimedia Authentication Answer
        elif (
            packet_vars["command_code"] == 303
            and packet_vars["ApplicationId"] == 16777216
        ):
            self.logger.info(
                f"Received Request with command code 303 (3GPP Cx Multimedia Authentication Request) from {origin_host}"
                + "\n\tGenerating (MAA)"
            )
            try:
                response = diameter.Answer_16777216_303(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as e:
                self.logger.info(
                    "Failed to generate Diameter Response for Cx Multimedia Authentication Answer"
                )
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 4100
                )  # DIAMETER_USER_DATA_NOT_AVAILABLE
            self.logger.info("Generated Cx Multimedia Authentication Answer")

        # Sh User-Data-Answer
        elif (
            packet_vars["command_code"] == 306
            and packet_vars["ApplicationId"] == 16777217
        ):
            self.logger.info(
                f"Received Request with command code 306 (3GPP Sh User-Data Request) from {origin_host}"
            )
            try:
                response = diameter.Answer_16777217_306(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as e:
                self.logger.info(
                    "Failed to generate Diameter Response for Sh User-Data Answer"
                )
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 5001
                )  # DIAMETER_ERROR_USER_UNKNOWN
                clientsocket.sendall(bytes.fromhex(response))
                self.logger.info("Sent negative response")
                return
            self.logger.info("Generated Sh User-Data Answer")

        # Sh Profile-Update-Answer
        elif (
            packet_vars["command_code"] == 307
            and packet_vars["ApplicationId"] == 16777217
        ):
            self.logger.info(
                f"Received Request with command code 307 (3GPP Sh Profile-Update Request) from {origin_host}"
            )
            try:
                response = diameter.Answer_16777217_307(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as e:
                self.logger.info(
                    "Failed to generate Diameter Response for Sh User-Data Answer"
                )
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 5001
                )  # DIAMETER_ERROR_USER_UNKNOWN
                clientsocket.sendall(bytes.fromhex(response))
                self.logger.info("Sent negative response")
                return
            self.logger.info("Generated Sh Profile-Update Answer")

        # S13 ME-Identity-Check Answer
        elif (
            packet_vars["command_code"] == 324
            and packet_vars["ApplicationId"] == 16777252
        ):
            self.logger.info(
                f"Received Request with command code 324 (3GPP S13 ME-Identity-Check Request) from {origin_host}"
                + "\n\tGenerating (MICA)"
            )
            try:
                response = diameter.Answer_16777252_324(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as e:
                self.logger.info(
                    "Failed to generate Diameter Response for S13 ME-Identity Check Answer"
                )
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 4100
                )  # DIAMETER_USER_DATA_NOT_AVAILABLE
            self.logger.info("Generated S13 ME-Identity Check Answer")

        # SLh LCS-Routing-Info-Answer
        elif (
            packet_vars["command_code"] == 8388622
            and packet_vars["ApplicationId"] == 16777291
        ):
            self.logger.info(
                f"Received Request with command code 324 (3GPP SLh LCS-Routing-Info-Answer Request) from {origin_host}"
                + "\n\tGenerating (MICA)"
            )
            try:
                response = diameter.Answer_16777291_8388622(
                    packet_vars, avps
                )  # Generate Diameter packet
            except Exception as e:
                self.logger.info(
                    "Failed to generate Diameter Response for SLh LCS-Routing-Info-Answer"
                )
                self.logger.info(e)
                traceback.print_exc()
                response = diameter.Respond_ResultCode(
                    packet_vars, avps, 4100
                )  # DIAMETER_USER_DATA_NOT_AVAILABLE
            self.logger.info("Generated SLh LCS-Routing-Info-Answer")

        # Handle Responses generated by the Async functions
        elif packet_vars["flags"] == "00":
            self.logger.info(
                "Got response back with command code "
                + str(packet_vars["command_code"])
            )
            self.logger.info("response packet_vars: " + str(packet_vars))
            self.logger.info("response avps: " + str(avps))
            response = ""
        else:
            self.logger.error(
                "\n\nRecieved unrecognised request with Command Code: "
                + str(packet_vars["command_code"])
                + ", ApplicationID: "
                + str(packet_vars["ApplicationId"])
                + " and flags "
                + str(packet_vars["flags"])
            )
            for keys in packet_vars:
                self.logger.error(keys)
                self.logger.error("\t" + str(packet_vars[keys]))
            self.logger.error(avps)
            self.logger.error("Sending negative response")
            response = diameter.Respond_ResultCode(
                packet_vars, avps, 3001
            )  # Generate Diameter response with "Command Unsupported" (3001)
            clientsocket.sendall(bytes.fromhex(response))  # Send it

        prom_diam_response_time_method.labels(
            str(packet_vars["ApplicationId"]),
            str(packet_vars["command_code"]),
            origin_host,
            "request",
        ).observe(time.time() - start_time)

        # Handle actual sending
        try:
            clientsocket.sendall(bytes.fromhex(response))  # Send it
        except Exception as e:
            self.logger.info("Failed to send Diameter Response")
            self.logger.debug(f"Diameter Response Body: {str(response)}")
            self.logger.info(e)
            traceback.print_exc()

    def manage_client(self, clientsocket, client_address, diameter, thread_event):
        data_sum = b""
        while True:
            try:
                data = clientsocket.recv(32)
                if not data:
                    self.logger.info(f"Connection closed by {str(client_address)}")
                    self.logtool.Manage_Diameter_Peer(
                        client_address, client_address, "remove"
                    )
                    thread_event.set()
                    break
                self.process_Diameter_request(
                    clientsocket, client_address, diameter, data
                )

            except KeyboardInterrupt:
                # Clean up the connection on keyboard interrupt
                response = (
                    diameter.Request_282()
                )  # Generate Disconnect Peer Request Diameter packet
                clientsocket.sendall(bytes.fromhex(response))  # Send it
                clientsocket.close()
                self.logger.info("Connection closed niceley due to keyboard interrupt")
                sys.exit()

            except Exception as manage_client_exception:
                self.logger.error(
                    f"Exception in manage_client: {manage_client_exception}"
                )
                return

    def manage_client_async(self, clientsocket, client_address, diameter, thread_event):
        # Sleep for 30 seconds to wait for the Connection to come up
        time.sleep(10)
        self.logger.debug("Async Getting ActivePeerDict")
        self.logger.debug(
            f"Async: Total PyHSS Active Threads: {threading.active_count()}"
        )
        ActivePeerDict = self.logtool.GetDiameterPeers()
        self.logger.debug(
            f"Async Got Active Peer dict in Async Thread: {str(ActivePeerDict)}"
        )
        if client_address[0] in ActivePeerDict:
            self.logger.debug(
                "Async This is host: "
                + str(ActivePeerDict[str(client_address[0])]["DiameterHostname"])
            )
            DiameterHostname = str(
                ActivePeerDict[str(client_address[0])]["DiameterHostname"]
            )
        else:
            self.logger.debug("Async No matching Diameter Host found.")
            return

        while True:
            try:
                if thread_event.is_set():
                    self.logger.debug(
                        f"Closing manage_client_async thread for client: {client_address}"
                    )
                    return
                time.sleep(self.yaml_config["hss"]["async_check_interval"])
                self.logger.debug(
                    f"Async sleep interval expired for Diameter Peer {str(DiameterHostname)}"
                )
            except:
                self.logger.error(
                    f"Async No async_check_interval Timer set - Not checking Async Queue for host connection {str(DiameterHostname)}"
                )
                break
            if int(self.yaml_config["hss"]["async_check_interval"]) == 0:
                self.logger.error(
                    f"Async No async_check_interval Timer set - Not checking Async Queue for host connection {str(DiameterHostname)}"
                )
                break
            try:
                self.logger.debug(
                    "Async Reading from request Queue '"
                    + str(DiameterHostname)
                    + "_request_queue'"
                )
                data_to_send = self.logtool.RedisHMGET(
                    str(DiameterHostname) + "_request_queue"
                )
                self.logger.debug(data_to_send)
                for key in data_to_send:
                    self.logger.debug(
                        "Sending key " + str(key) + " to " + str(DiameterHostname)
                    )
                    data = data_to_send[key].decode("utf-8")
                    self.logger.debug("Sending Hex Data: " + str(data))
                    clientsocket.sendall(bytes.fromhex(data))
                    self.logtool.RedisHDEL(
                        str(DiameterHostname) + "_request_queue", key
                    )
            except:
                continue
        self.logger.debug("Async Left manage_client_async() for this thread")
        return

    def manage_client_dwr(self, clientsocket, client_address, diameter, thread_event):
        while True:
            try:
                if thread_event.is_set():
                    self.logger.debug(
                        f"Closing manage_client_dwr thread for client: {client_address}"
                    )
                    return
                if (
                    int(self.yaml_config["hss"]["device_watchdog_request_interval"])
                    != 0
                ):
                    time.sleep(
                        self.yaml_config["hss"]["device_watchdog_request_interval"]
                    )
                else:
                    self.logger.info("DWR Timer to set to 0 - Not sending DWRs")
                    return

            except:
                self.logger.error(
                    "No DWR Timer set - Not sending Device Watchdog Requests"
                )
                return
            self.logger.debug("Sending Keepalive to " + str(client_address) + "...")
            request = diameter.Request_280()
            clientsocket.sendall(bytes.fromhex(request))  # Send it
            self.logger.debug("Sent Keepalive to " + str(client_address) + "...")
        self.logger.debug("Async Left manage_client_async() for this thread")
        return

    def get_socket_family(self):
        if ":" in self.yaml_config["hss"]["bind_ip"][0]:
            self.logger.info("IPv6 Address Specified")
            return socket.AF_INET6
        else:
            self.logger.info("IPv4 Address Specified")
            return socket.AF_INET

    def start_server(self):
        if self.yaml_config["hss"]["transport"] == "SCTP":
            self.logger.debug("Using SCTP for Transport")
            # Create a SCTP socket
            sock = sctp.sctpsocket_tcp(self.get_socket_family())
            sock.initparams.num_ostreams = 64
            # Loop through the possible Binding IPs from the config and bind to each for Multihoming
            server_addresses = []

            # Prepend each entry into list, so the primary IP is bound first
            for host in self.yaml_config["hss"]["bind_ip"]:
                self.logger.info("Seting up SCTP binding on IP address " + str(host))
                this_IP_binding = [
                    (str(host), int(self.yaml_config["hss"]["bind_port"]))
                ]
                server_addresses = this_IP_binding + server_addresses

            print("server_addresses are: " + str(server_addresses))
            sock.bindx(server_addresses)
            self.logger.info("PyHSS listening on SCTP port " + str(server_addresses))
            systemd.daemon.notify("READY=1")
            # Listen for up to 5 incoming connection
            sock.listen(5)
        elif self.yaml_config["hss"]["transport"] == "TCP":
            self.logger.debug("Using TCP socket")
            # Create a TCP/IP socket
            sock = socket.socket(self.get_socket_family(), socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the socket to the port
            server_address = (
                str(self.yaml_config["hss"]["bind_ip"][0]),
                int(self.yaml_config["hss"]["bind_port"]),
            )
            sock.bind(server_address)
            self.logger.debug(
                "PyHSS listening on TCP port "
                + str(self.yaml_config["hss"]["bind_ip"][0])
            )
            systemd.daemon.notify("READY=1")
            # Listen for up to 10 incoming connections
            sock.listen(10)
        else:
            self.logger.error("No valid transports found (No SCTP or TCP) - Exiting")
            sys.exit()

        while True:
            # Wait for a connection
            self.logger.info("Waiting for a connection...")
            connection, client_address = sock.accept()
            _thread.start_new_thread(
                self.handle_new_connection,
                (
                    connection,
                    client_address,
                ),
            )


if __name__ == "__main__":
    pyHss = PyHSS()
    pyHss.start_server()
