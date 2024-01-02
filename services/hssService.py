import os, sys, json, yaml, time, traceback
sys.path.append(os.path.realpath('../lib'))
from messaging import RedisMessaging
from diameter import Diameter
from banners import Banners
from logtool import LogTool

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

    def handleQueue(self):
        """
        Gets and parses inbound diameter requests, processes them and queues the response.
        """
        while True:
            try:
                if self.benchmarking:
                    startTime = time.perf_counter()

                inboundMessageList = self.redisMessaging.awaitBulkMessage(key='diameter-inbound')

                if inboundMessageList == None:
                    continue
                for inboundMessage in inboundMessageList[1]:
                    self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] Message: {inboundMessage}", redisClient=self.redisMessaging)

                    inboundMessage = json.loads(inboundMessage.decode('ascii'))
                    inboundBinary = bytes.fromhex(inboundMessage.get('diameter-inbound', None))

                    if inboundBinary == None:
                        continue
                    inboundHost = inboundMessage.get('clientAddress', None)
                    inboundPort = inboundMessage.get('clientPort', None)
                    inboundTimestamp = inboundMessage.get('inbound-received-timestamp', None)

                    try:
                        diameterPeers = json.loads(self.redisMessaging.getValue("ActiveDiameterPeers"))

                        for diameterPeer in diameterPeers:
                            if diameterPeers[diameterPeer].get('ipAddress', '') == inboundHost and diameterPeers[diameterPeer].get('port', '') == inboundPort:
                                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_request_count_host',
                                            metricType='gauge', metricAction='inc',
                                            metricLabels={
                                            "host": diameterPeers[diameterPeer]['diameterHostname']},
                                            metricValue=float(1), metricHelp='Number of Diameter Requests Recieved per Host',
                                            metricExpiry=60)

                    except Exception as e:
                        pass

                    try:
                        diameterOutbound = self.diameterLibrary.generateDiameterResponse(binaryData=inboundBinary)

                        if diameterOutbound == None:
                            continue
                        if not len(diameterOutbound) > 0:
                            continue

                        diameterMessageTypeDict = self.diameterLibrary.getDiameterMessageType(binaryData=inboundBinary)
                        
                        if diameterMessageTypeDict == None:
                            continue
                        if not len(diameterMessageTypeDict) > 0:
                            continue

                        diameterMessageTypeInbound = diameterMessageTypeDict.get('inbound', '')
                        diameterMessageTypeOutbound = diameterMessageTypeDict.get('outbound', '')
                    except Exception as e:
                        self.logTool.log(service='HSS', level='warning', message=f"[HSS] [handleQueue] Failed to generate diameter outbound: {e}", redisClient=self.redisMessaging)
                        continue

                    self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] [{diameterMessageTypeInbound}] Inbound Diameter Inbound: {inboundMessage}", redisClient=self.redisMessaging)
                    
                    outboundQueue = f"diameter-outbound-{inboundHost}-{inboundPort}"
                    outboundMessage = json.dumps({"diameter-outbound": diameterOutbound, "inbound-received-timestamp": inboundTimestamp})

                    self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] [{diameterMessageTypeOutbound}] Generated Diameter Outbound: {diameterOutbound}", redisClient=self.redisMessaging)
                    self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] [{diameterMessageTypeOutbound}] Outbound Diameter Outbound Queue: {outboundQueue}", redisClient=self.redisMessaging)
                    self.logTool.log(service='HSS', level='debug', message=f"[HSS] [handleQueue] [{diameterMessageTypeOutbound}] Outbound Diameter Outbound: {outboundMessage}", redisClient=self.redisMessaging)

                    self.redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage, queueExpiry=60)
                    if self.benchmarking:
                        self.logTool.log(service='HSS', level='info', message=f"[HSS] [handleQueue] [{diameterMessageTypeInbound}] Time taken to process request: {round(((time.perf_counter() - startTime)*1000), 3)} ms", redisClient=self.redisMessaging)

                    try:
                        diameterPeers = json.loads(self.redisMessaging.getValue("ActiveDiameterPeers"))

                        for diameterPeer in diameterPeers:
                            if diameterPeers[diameterPeer].get('ipAddress', '') == inboundHost and diameterPeers[diameterPeer].get('port', '') == inboundPort:
                                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_response_count_host',
                                            metricType='gauge', metricAction='inc',
                                            metricLabels={
                                            "host": diameterPeers[diameterPeer]['diameterHostname']},
                                            metricValue=float(1), metricHelp='Number of Diameter Responses Sent per Host',
                                            metricExpiry=60)

                    except Exception as e:
                        pass


            except Exception as e:
                self.logTool.log(service='HSS', level='error', message=f"[HSS] [handleQueue] Exception: {traceback.format_exc()}", redisClient=self.redisMessaging)
                continue
            


if __name__ == '__main__':
    hssService = HssService()
    hssService.handleQueue()