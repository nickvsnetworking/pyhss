#!/usr/bin/env python3
"""
HSS Service mit Zn-Interface Integration
Zeigt wie das Zn-Interface in den bestehenden PyHSS Service integriert wird
"""

import os, sys, json, yaml, time, traceback, socket

sys.path.insert(0, os.path.realpath('../lib'))

# Bestehende PyHSS Imports
from diameter import Diameter
from database import Database
from logtool import LogTool
from messaging import RedisMessaging
from banners import Banners
from baseModels import Peer, InboundData, OutboundData
import pydantic_core

# Neue Zn-Interface Imports
from zn_interface import initialize_zn_interface, ZnInterface, ZnDiameterExtension

class HssService:
    
    def __init__(self):

        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[HSS] Fatal Error - config.yaml not found, exiting.")
            quit()
        self.redisUseUnixSocket = self.config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = self.config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = self.config.get('redis', {}).get('host', 'localhost')
        self.redisPort = self.config.get('redis', {}).get('port', 6379)
        self.redisMessaging = RedisMessaging(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.logTool = LogTool(config=self.config)
        self.banners = Banners()
        self.mnc = self.config.get('hss', {}).get('MNC', '999')
        self.mcc = self.config.get('hss', {}).get('MCC', '999')
        self.originRealm = self.config.get('hss', {}).get('OriginRealm', f'mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org')
        self.originHost = self.config.get('hss', {}).get('OriginHost', f'hss01')
        self.productName = self.config.get('hss', {}).get('ProductName', f'PyHSS')
        self.logTool.log(service='HSS', level='info', message=f"{self.banners.hssService()}", redisClient=self.redisMessaging)
        self.diameterLibrary = Diameter(logTool=self.logTool, originHost=self.originHost, originRealm=self.originRealm, productName=self.productName, mcc=self.mcc, mnc=self.mnc)
        self.benchmarking = self.config.get('hss').get('enable_benchmarking', False)
        self.hostname = socket.gethostname()
        self.diameterPeerKey = self.config.get('hss', {}).get('diameter_peer_key', 'diameterPeers')

        # Zn-Interface initialisieren (wenn aktiviert)
        zn_enabled = self.config.get('hss', {}).get('Zn_enabled', False)
        
        if zn_enabled:
            self.logTool.log(
                service='HSS',
                level='info',
                message="Zn-Interface is enabled, initializing...",
                redisClient=self.redisMessaging
            )
            
            try:
                # Zn-Interface Extension registrieren
                zn_extension, zn_interface = initialize_zn_interface(self.diameterLibrary, self.config)
                
                self.logTool.log(
                    service='HSS',
                    level='info',
                    message="Zn-Interface successfully initialized and registered",
                    redisClient=self.redisMessaging
                )
                
            except Exception as e:
                self.logTool.log(
                    service='HSS',
                    level='error',
                    message=f"Failed to initialize Zn-Interface: {str(e)}",
                    redisClient=self.redisMessaging
                )
                raise
        else:
            self.logTool.log(
                service='HSS',
                level='info',
                message="Zn-Interface is disabled in configuration",
                redisClient=self.redisMessaging
            )

    def handleQueue(self):
        """
        Gets and parses inbound diameter requests, processes them and queues the response.
        """
        while True:
            try:
                if self.benchmarking:
                    startTime = time.perf_counter()

                inboundMessageList = self.redisMessaging.awaitBulkMessage(key='diameter-inbound', usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')

                if inboundMessageList == None:
                    continue
                for inboundMessage in inboundMessageList[1]:
                    self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] Message: {inboundMessage}", redisClient=self.redisMessaging)
                    inboundMessage = inboundMessage.decode('ascii')
                    inboundData = InboundData.model_validate(pydantic_core.from_json(inboundMessage))
                    inboundBinary = bytes.fromhex(inboundData.InboundHex)

                    if inboundBinary == None:
                        continue

                    buffered_diameter_messages = self.diameterLibrary.split_diameter_message(inboundBinary)
                    self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] Buffered diameter messages: {buffered_diameter_messages}", redisClient=self.redisMessaging)
                    messageNumber = 1

                    for buffered_diameter_message in buffered_diameter_messages:
                        self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] Processing message ({messageNumber} of {len(buffered_diameter_messages)}): {buffered_diameter_message}", redisClient=self.redisMessaging)

                        try:
                            diameterPeers = self.redisMessaging.getAllHashData(self.diameterPeerKey, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                            if diameterPeers:
                                for diameterPeerKey, diameterPeerValue in diameterPeers.items():
                                    diameterPeer = Peer.model_validate(pydantic_core.from_json(json.dumps(diameterPeerValue)))
                                    # If this is a message from a stored peer, increment prom_diam_request_count_host by 1.
                                    if diameterPeer.IpAddress == inboundData.SenderIp and diameterPeer.Port == inboundData.SenderPort:
                                        self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_request_count_host',
                                                    metricType='gauge', metricAction='inc',
                                                    metricLabels={
                                                    "host": diameterPeer.Hostname},
                                                    metricValue=float(1), metricHelp='Number of Diameter Requests Recieved per Host',
                                                    metricExpiry=60,
                                                    usePrefix=True, 
                                                    prefixHostname=self.hostname, 
                                                    prefixServiceName='metric')

                        except Exception as e:
                            self.logTool.log(service='HSS', level='error', message=f"[HSS] [handleQueue] Error updating prom_diam_request_count_host: {traceback.format_exc()}", redisClient=self.redisMessaging)
                            pass

                        try:
                            messageBinary = bytes.fromhex(buffered_diameter_message)
                            diameterOutbound = self.diameterLibrary.generateDiameterResponse(binaryData=messageBinary)

                            if diameterOutbound == None:
                                continue
                            if not len(diameterOutbound) > 0:
                                continue

                            diameterMessageTypeDict = self.diameterLibrary.getDiameterMessageType(binaryData=messageBinary)
                            
                            if diameterMessageTypeDict == None:
                                continue
                            if not len(diameterMessageTypeDict) > 0:
                                continue

                            diameterMessageTypeInbound = diameterMessageTypeDict.get('inbound', '')
                            diameterMessageTypeOutbound = diameterMessageTypeDict.get('outbound', '')
                        except Exception as e:
                            self.logTool.log(service='HSS', level='warning', message=f"[HSS] [handleQueue] Failed to generate diameter outbound: {e}", redisClient=self.redisMessaging)
                            continue
                        
                        outboundQueue = f"diameter-outbound-{inboundData.SenderIp}-{inboundData.SenderPort}"
                        outboundMessage = OutboundData(DestinationIp=inboundData.SenderIp,
                                                    DestinationPort=inboundData.SenderPort,
                                                    InitialReceiveTimestamp=inboundData.InitialReceiveTimestamp,
                                                    OutboundHex=diameterOutbound)

                        self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] [{diameterMessageTypeOutbound}] Generated Diameter Outbound: {diameterOutbound}", redisClient=self.redisMessaging)
                        self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] [{diameterMessageTypeOutbound}] Outbound Diameter Queue: {outboundQueue}", redisClient=self.redisMessaging)
                        self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] [{diameterMessageTypeOutbound}] Outbound Diameter: {outboundMessage}", redisClient=self.redisMessaging)

                        self.redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage.model_dump_json(), queueExpiry=60, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                        messageNumber += 1
                        if self.benchmarking:
                            self.logTool.log(service='HSS', level='info', message=f"[HSS] [handleQueue] [{diameterMessageTypeInbound}] Time taken to process request: {round(((time.perf_counter() - startTime)*1000), 3)} ms", redisClient=self.redisMessaging)

                        try:
                            self.diameterLibrary.clear_expired_emergency_subscribers()
                            diameterPeers = self.redisMessaging.getAllHashData(self.diameterPeerKey, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                            if diameterPeers:
                                for diameterPeerKey, diameterPeerValue in diameterPeers.items():
                                    diameterPeer = Peer.model_validate(pydantic_core.from_json(json.dumps(diameterPeerValue)))
                                    if diameterPeer.IpAddress == inboundData.SenderIp and diameterPeer.Port == inboundData.SenderPort:
                                        self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_response_count_host',
                                                    metricType='gauge', metricAction='inc',
                                                    metricLabels={
                                                    "host": diameterPeer.Hostname},
                                                    metricValue=float(1), metricHelp='Number of Diameter Responses Sent per Host',
                                                    metricExpiry=60,
                                                    usePrefix=True, 
                                                    prefixHostname=self.hostname, 
                                                    prefixServiceName='metric')

                        except Exception as e:
                            self.logTool.log(service='HSS', level='error', message=f"[HSS] [handleQueue] Error updating prom_diam_response_count_host: {traceback.format_exc()}", redisClient=self.redisMessaging)
                            pass


            except Exception as e:
                self.logTool.log(service='HSS', level='error', message=f"[HSS] [handleQueue] Exception: {traceback.format_exc()}", redisClient=self.redisMessaging)
                continue
            
def main():
    """
    Hauptfunktion - Startet den HSS Service
    """
    try:
        # Service initialisieren
        hssService = HssService()
        print("HSS Service started successfully")
        print(f"Origin-Host: {hssService.diameterLibrary.OriginHost}")
        print(f"Origin-Realm: {hssService.diameterLibrary.OriginRealm}")
        
        # Zeige ob Zn-Interface aktiv ist
        if hssService.config.get('hss', {}).get('Zn_enabled', False):
            print("✓ Zn-Interface (GBA) enabled")
            bsf_hostname = hssService.config.get('hss', {}).get('bsf', {}).get('bsf_hostname', 'N/A')
            print(f"  BSF Hostname: {bsf_hostname}")
        else:
            print("✗ Zn-Interface (GBA) disabled")

        hssService.handleQueue()

    except KeyboardInterrupt:
        print("\nShutting down HSS Service...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
