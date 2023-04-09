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
import contextlib
import queue


class ThreadJoiner:
    def __init__(self, threads, thread_event):
        self.threads = threads
        self.thread_event = thread_event

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.thread_event.set()
        for thread in self.threads:
            while thread.is_alive():
                try:
                    thread.join(timeout=1)
                except Exception as e:
                    print(
                        f"ThreadJoiner Exception: failed to join thread {thread}: {e}"
                    )
                    break


class PyHSS:
    def __init__(self):
        # Load config from yaml file
        try:
            with open("config.yaml", "r") as config_stream:
                self.yaml_config = yaml.safe_load(config_stream)
        except:
            print(f"config.yaml not found, exiting PyHSS.")
            quit()

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

        self.max_diameter_retries = int(
            self.yaml_config["hss"].get("diameter_max_retries", 1)
        )

    def terminate_connection(self, clientsocket, client_address, thread_event):
        thread_event.set()
        clientsocket.close()
        self.logtool.Manage_Diameter_Peer(client_address, client_address, "remove")

    def handle_new_connection(self, clientsocket, client_address):
        # Create our threading event, accessible by sibling threads in this connection.
        socket_close_event = threading.Event()
        try:
            send_queue = queue.Queue()
            self.logger.debug(f"New connection from {client_address}")
            if (
                "client_socket_timeout" not in self.yaml_config["hss"]
                or self.yaml_config["hss"]["client_socket_timeout"] == 0
            ):
                self.yaml_config["hss"]["client_socket_timeout"] = 120
            clientsocket.settimeout(
                self.yaml_config["hss"].get("client_socket_timeout", 120)
            )

            send_data_thread = threading.Thread(
                target=self.send_data,
                name=f"send_data_thread",
                args=(clientsocket, send_queue, socket_close_event),
            )
            self.logger.debug("handle_new_connection: Starting send_data thread")
            send_data_thread.start()

            self.logtool.Manage_Diameter_Peer(client_address, client_address, "add")
            manage_client_thread = threading.Thread(
                target=self.manage_client,
                name=f"manage_client_thread: client_address: {client_address}",
                args=(
                    clientsocket,
                    client_address,
                    self.diameter_instance,
                    socket_close_event,
                    send_queue,
                ),
            )
            self.logger.debug("handle_new_connection: Starting manage_client thread")
            manage_client_thread.start()

            threads_to_join = [manage_client_thread]
            threads_to_join.append(send_data_thread)

            # If Redis is enabled, start manage_client_async and manage_client_dwr threads.
            if self.yaml_config["redis"]["enabled"]:
                if (
                    "async_check_interval" not in self.yaml_config["hss"]
                    or self.yaml_config["hss"]["async_check_interval"] == 0
                ):
                    self.yaml_config["hss"]["async_check_interval"] = 10
                manage_client_async_thread = threading.Thread(
                    target=self.manage_client_async,
                    name=f"manage_client_async_thread: client_address: {client_address}",
                    args=(
                        clientsocket,
                        client_address,
                        self.diameter_instance,
                        socket_close_event,
                        send_queue,
                    ),
                )
                self.logger.debug(
                    "handle_new_connection: Starting manage_client_async thread"
                )
                manage_client_async_thread.start()

                manage_client_dwr_thread = threading.Thread(
                    target=self.manage_client_dwr,
                    name=f"manage_client_dwr_thread: client_address: {client_address}",
                    args=(
                        clientsocket,
                        client_address,
                        self.diameter_instance,
                        socket_close_event,
                        send_queue,
                    ),
                )
                self.logger.debug(
                    "handle_new_connection: Starting manage_client_dwr thread"
                )
                manage_client_dwr_thread.start()

                threads_to_join.append(manage_client_async_thread)
                threads_to_join.append(manage_client_dwr_thread)

            self.logger.debug(
                f"handle_new_connection: Total PyHSS Active Threads: {threading.active_count()}"
            )
            for thread in threading.enumerate():
                if "dummy" not in thread.name.lower():
                    self.logger.debug(f"Active Thread name: {thread.name}")

            with ThreadJoiner(threads_to_join, socket_close_event):
                socket_close_event.wait()
                self.terminate_connection(
                    clientsocket, client_address, socket_close_event
                )
                self.logger.debug(f"Closing thread for client; {client_address}")
                return

        except Exception as e:
            self.logger.error(f"Exception for client {client_address}: {e}")
            self.logger.error(f"Closing connection for {client_address}")
            self.terminate_connection(clientsocket, client_address, socket_close_event)
            return

    @prom_diam_response_time_diam.time()
    def process_Diameter_request(
        self, clientsocket, client_address, diameter, data, thread_event, send_queue
    ):
        packet_length = diameter.decode_diameter_packet_length(
            data
        )  # Calculate length of packet from start of packet
        if packet_length <= 32:
            self.logger.error("Received an invalid packet with length <= 32")
            self.terminate_connection(clientsocket, client_address, thread_event)
            return

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
            self.logger.debug(f"Total PyHSS Active Threads: {threading.active_count()}")
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
                    send_queue.put(bytes.fromhex(response))
                    # clientsocket.sendall(bytes.fromhex(response))
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
                send_queue.put(bytes.fromhex(response))
                # clientsocket.sendall(bytes.fromhex(response))
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
                send_queue.put(bytes.fromhex(response))
                # clientsocket.sendall(bytes.fromhex(response))
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
            send_queue.put(bytes.fromhex(response))
            # clientsocket.sendall(bytes.fromhex(response))  # Send it

        prom_diam_response_time_method.labels(
            str(packet_vars["ApplicationId"]),
            str(packet_vars["command_code"]),
            origin_host,
            "request",
        ).observe(time.time() - start_time)

        # Diameter Transmission
        retries = 0
        while retries < self.max_diameter_retries:
            try:
                send_queue.put(bytes.fromhex(response))
                break
            except socket.error as e:
                self.logger.error(f"Socket error for client {client_address}: {e}")
                retries += 1
                if retries > self.max_diameter_retries:
                    self.logger.error(
                        f"Max retries reached for client {client_address}. Closing connection."
                    )
                    self.terminate_connection(
                        clientsocket, client_address, thread_event
                    )
                    break
                time.sleep(1)  # Wait for 1 second before retrying
            except Exception as e:
                self.logger.info("Failed to send Diameter Response")
                self.logger.debug(f"Diameter Response Body: {str(response)}")
                self.logger.info(e)
                traceback.print_exc()
                self.terminate_connection(clientsocket, client_address, thread_event)
                self.logger.info("Thread terminated to " + str(client_address))
                break

    def manage_client(
        self, clientsocket, client_address, diameter, thread_event, send_queue
    ):
        while True:
            try:
                data = clientsocket.recv(32)
                if not data:
                    self.logger.info(
                        f"manage_client: Connection closed by {str(client_address)}"
                    )
                    self.terminate_connection(
                        clientsocket, client_address, thread_event
                    )
                    return
                self.process_Diameter_request(
                    clientsocket,
                    client_address,
                    diameter,
                    data,
                    thread_event,
                    send_queue,
                )

            except socket.timeout:
                self.logger.warning(
                    f"manage_client: Socket timeout for client: {client_address}"
                )
                self.terminate_connection(clientsocket, client_address, thread_event)
                return

            except socket.error as e:
                self.logger.error(
                    f"manage_client: Socket error for client {client_address}: {e}"
                )
                self.terminate_connection(clientsocket, client_address, thread_event)
                return

            except KeyboardInterrupt:
                # Clean up the connection on keyboard interrupt
                response = (
                    diameter.Request_282()
                )  # Generate Disconnect Peer Request Diameter packet
                send_queue.put(bytes.fromhex(response))
                # clientsocket.sendall(bytes.fromhex(response))  # Send it
                self.terminate_connection(clientsocket, client_address, thread_event)
                self.logger.info(
                    "manage_client: Connection closed nicely due to keyboard interrupt"
                )
                sys.exit()

            except Exception as manage_client_exception:
                self.logger.error(
                    f"manage_client: Exception in manage_client: {manage_client_exception}"
                )
                self.terminate_connection(clientsocket, client_address, thread_event)
                return

    def manage_client_async(
        self, clientsocket, client_address, diameter, thread_event, send_queue
    ):
        # # Sleep for 10 seconds to wait for the connection to come up
        time.sleep(10)
        self.logger.debug("manage_client_async: Getting ActivePeerDict")
        self.logger.debug(
            f"manage_client_async: Total PyHSS Active Threads: {threading.active_count()}"
        )
        ActivePeerDict = self.logtool.GetDiameterPeers()
        self.logger.debug(
            f"manage_client_async: Got Active Peer dict in Async Thread: {str(ActivePeerDict)}"
        )
        if client_address[0] in ActivePeerDict:
            self.logger.debug(
                "manage_client_async: This is host: "
                + str(ActivePeerDict[str(client_address[0])]["DiameterHostname"])
            )
            DiameterHostname = str(
                ActivePeerDict[str(client_address[0])]["DiameterHostname"]
            )
        else:
            self.logger.debug("manage_client_async: No matching Diameter Host found.")
            return

        while True:
            try:
                if thread_event.is_set():
                    self.logger.debug(
                        f"manage_client_async: Closing manage_client_async thread for client: {client_address}"
                    )
                    self.terminate_connection(
                        clientsocket, client_address, thread_event
                    )
                    return
                time.sleep(self.yaml_config["hss"]["async_check_interval"])
                self.logger.debug(
                    f"manage_client_async: Sleep interval expired for Diameter Peer {str(DiameterHostname)}"
                )
                if int(self.yaml_config["hss"]["async_check_interval"]) == 0:
                    self.logger.error(
                        f"manage_client_async: No async_check_interval Timer set - Not checking Async Queue for host connection {str(DiameterHostname)}"
                    )
                    return
                try:
                    self.logger.debug(
                        "manage_client_async: Reading from request queue '"
                        + str(DiameterHostname)
                        + "_request_queue'"
                    )
                    data_to_send = self.logtool.RedisHMGET(
                        str(DiameterHostname) + "_request_queue"
                    )
                    for key in data_to_send:
                        data = data_to_send[key].decode("utf-8")
                        send_queue.put(bytes.fromhex(data))
                        self.logtool.RedisHDEL(
                            str(DiameterHostname) + "_request_queue", key
                        )
                except Exception as redis_exception:
                    self.logger.error(
                        f"manage_client_async: Redis exception in manage_client_async: {redis_exception}"
                    )
                    self.terminate_connection(
                        clientsocket, client_address, thread_event
                    )
                    return

            except socket.timeout:
                self.logger.warning(
                    f"manage_client_async: Socket timeout for client: {client_address}"
                )
                self.terminate_connection(clientsocket, client_address, thread_event)
                return

            except socket.error as e:
                self.logger.error(
                    f"manage_client_async: Socket error for client {client_address}: {e}"
                )
                self.terminate_connection(clientsocket, client_address, thread_event)
                return
            except Exception:
                self.logger.error(
                    f"manage_client_async: Terminating for host connection {str(DiameterHostname)}"
                )
                self.terminate_connection(clientsocket, client_address, thread_event)
                return

    def manage_client_dwr(
        self, clientsocket, client_address, diameter, thread_event, send_queue
    ):
        while True:
            try:
                if thread_event.is_set():
                    self.logger.debug(
                        f"Closing manage_client_dwr thread for client: {client_address}"
                    )
                    self.terminate_connection(
                        clientsocket, client_address, thread_event
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
            try:
                self.logger.debug("Sending Keepalive to " + str(client_address) + "...")
                request = diameter.Request_280()
                send_queue.put(bytes.fromhex(request))
                # clientsocket.sendall(bytes.fromhex(request))  # Send it
                self.logger.debug("Sent Keepalive to " + str(client_address) + "...")
            except socket.error as e:
                self.logger.error(
                    f"manage_client_dwr: Socket error for client {client_address}: {e}"
                )
                self.terminate_connection(clientsocket, client_address, thread_event)
                return
            except Exception as e:
                self.logger.error(
                    f"manage_client_dwr: General exception for client {client_address}: {e}"
                )
                self.terminate_connection(clientsocket, client_address, thread_event)

    def get_socket_family(self):
        if ":" in self.yaml_config["hss"]["bind_ip"][0]:
            self.logger.info("IPv6 Address Specified")
            return socket.AF_INET6
        else:
            self.logger.info("IPv4 Address Specified")
            return socket.AF_INET

    def send_data(self, clientsocket, send_queue, thread_event):
        while not thread_event.is_set():
            try:
                data = send_queue.get(timeout=1)
                # Check if data is bytes, otherwise convert it using bytes.fromhex()
                if not isinstance(data, bytes):
                    data = bytes.fromhex(data)

                clientsocket.sendall(data)
            except (
                queue.Empty
            ):  # Catch the Empty exception when the queue is empty and the timeout has expired
                continue
            except Exception as e:
                self.logger.error(f"send_data_thread: Exception: {e}")
                return

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
            # Listen for up to 20 incoming SCTP connections
            sock.listen(20)
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
            # Listen for up to 20 incoming TCP connections
            sock.listen(20)
        else:
            self.logger.error("No valid transports found (No SCTP or TCP) - Exiting")
            quit()

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
