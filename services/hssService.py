#!/usr/bin/env python3
# Copyright 2023-2025 David Kneipp <david@davidkneipp.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os, sys, json, time, traceback, socket

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))

from messaging import RedisMessaging
from diameter import Diameter
from banners import Banners
from logtool import LogTool
from baseModels import Peer, InboundData, OutboundData
import pydantic_core
from pyhss_config import config


class HssService:
    
    def __init__(self):
        self.redisUseUnixSocket = config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = config.get('redis', {}).get('host', 'localhost')
        self.redisPort = config.get('redis', {}).get('port', 6379)
        self.redisMessaging = RedisMessaging(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.logTool = LogTool(config=config)
        self.banners = Banners()
        self.mnc = config.get('hss', {}).get('MNC', '999')
        self.mcc = config.get('hss', {}).get('MCC', '999')
        self.originRealm = config.get('hss', {}).get('OriginRealm', f'mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org')
        self.originHost = config.get('hss', {}).get('OriginHost', f'hss01')
        self.productName = config.get('hss', {}).get('ProductName', f'PyHSS')
        self.logTool.log(service='HSS', level='info', message=f"{self.banners.hssService()}", redisClient=self.redisMessaging)
        self.diameterLibrary = Diameter(
            logTool=self.logTool,
            originHost=self.originHost,
            originRealm=self.originRealm,
            productName=self.productName,
            mcc=self.mcc,
            mnc=self.mnc,
            main_service=True,
        )
        self.benchmarking = config.get('hss').get('enable_benchmarking', False)
        self.hostname = self.originHost
        self.diameterPeerKey = config.get('hss', {}).get('diameter_peer_key', 'diameterPeers')

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
    hssService = HssService()
    hssService.handleQueue()


if __name__ == '__main__':
    main()
