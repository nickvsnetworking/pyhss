import asyncio
import sys, os, json
import time, yaml, uuid
from datetime import datetime
from tzlocal import get_localzone
import sctp, socket
sys.path.append(os.path.realpath('../lib'))
from messagingAsync import RedisMessagingAsync
from diameterAsync import DiameterAsync
from banners import Banners
from logtool import LogTool
from baseModels import Peer, InboundData, OutboundData
import pydantic_core
import traceback

class DiameterService:
    """
    PyHSS Diameter Service
    A class for handling diameter inbounds and replies on Port 3868, via TCP.
    Functions in this class are high-performance, please edit with care. Last profiled October 6th, 2023.
    """

    def __init__(self):
        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[Diameter] [__init__] Fatal Error - config.yaml not found, exiting.")
            quit()

        self.redisUseUnixSocket = self.config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = self.config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = self.config.get('redis', {}).get('host', 'localhost')
        self.redisPort = self.config.get('redis', {}).get('port', 6379)
        self.redisReaderMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.redisWriterMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.redisPeerMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.redisPeerLogMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.redisMetricMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.redisDwrMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.banners = Banners()
        self.logTool = LogTool(config=self.config)
        self.diameterLibrary = DiameterAsync(logTool=self.logTool)
        self.activePeers = {}
        self.enableOutboundDwr = self.config.get('hss', {}).get('send_dwr', False)
        self.outboundDwrInterval = int(self.config.get('hss', {}).get('send_dwr_interval', 5))
        self.originHost = self.config.get('hss', {}).get('OriginHost', 'hss01')
        self.originRealm = self.config.get('hss', {}).get('OriginRealm', "epc.mnc001.mcc001.3gppnetwork.org")
        self.diameterRequestTimeout = int(self.config.get('hss', {}).get('diameter_request_timeout', 10))
        self.benchmarking = self.config.get('benchmarking', {}).get('enabled', False)
        self.benchmarkingInterval = self.config.get('benchmarking', {}).get('reporting_interval', 3600)
        self.diameterRequests = 0
        self.diameterResponses = 0
        self.workerPoolSize = int(self.config.get('hss', {}).get('diameter_service_workers', 10))
        self.hostname = socket.gethostname()
        self.useExternalSocketService = self.config.get('hss', {}).get('use_external_socket_service', False)
        self.diameterPeerKey = self.config.get('hss', {}).get('diameter_peer_key', 'diameterPeers')
    
    async def validateDiameterInbound(self, clientAddress: str, clientPort: str, inboundData) -> bool:
        """
        Asynchronously validates a given diameter inbound, and increments the 'Number of Diameter Inbounds' metric.
        """
        try:
            packetVars, avps = await(self.diameterLibrary.decodeDiameterPacket(inboundData))
            originHost = (await(self.diameterLibrary.getAvpData(avps, 264)))[0]
            originHost = bytes.fromhex(originHost).decode("utf-8")
            peerType = await(self.diameterLibrary.getPeerType(originHost))
            self.activePeers[f"{clientAddress}-{clientPort}"].update(Hostname=originHost,
                                                                     Metadata=json.dumps({
                                                                         'DiameterPeerType': (peerType if peerType != None else 'Unknown')
                                                                    })
                                                                    )
            return True
        except Exception as e:
            await(self.logTool.logAsync(service='Diameter', level='warning', message=f"[Diameter] [validateDiameterInbound] Exception: {e}\n{traceback.format_exc()}"))
            await(self.logTool.logAsync(service='Diameter', level='warning', message=f"[Diameter] [validateDiameterInbound] AVPs: {avps}\nPacketVars: {packetVars}"))
            return False

    async def handleOutboundDwr(self) -> bool:
        """
        Asynchronously sends an outbound DWR every outboundDwrInterval to each connected peer, if enabled.
        """
        while True:
            try:
                outboundDwrEncoded = await(self.diameterLibrary.Request_280(originHost=self.originHost, originRealm=self.originRealm))
                activePeersCached = self.activePeers
                for activePeerKey, activePeerValue in activePeersCached.items():

                    isConnected = activePeerValue.Connected
                    peerIp = activePeerValue.IpAddress
                    peerPort = activePeerValue.Port
                    if not peerIp or not peerPort or not isConnected:
                        continue

                    outboundQueue = f"diameter-outbound-{peerIp}-{peerPort}"
                    outboundData = OutboundData(DestinationIp=peerIp,
                                                DestinationPort=peerPort,
                                                InitialReceiveTimestamp=time.time_ns(),
                                                OutboundHex=outboundDwrEncoded)
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [handleOutboundDwr] Sending Outbound DWR to: {outboundQueue}"))
                    await(self.redisDwrMessaging.sendMessage(queue=outboundQueue, message=outboundData.model_dump_json(), queueExpiry=60, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter'))
                await(asyncio.sleep(self.outboundDwrInterval))
                continue
            except Exception as e:
                await(self.logTool.logAsync(service='Diameter', level='warning', message=f"[Diameter] [handleOutboundDwr] Exception: {e}\n{traceback.format_exc()}"))
                await(asyncio.sleep(self.outboundDwrInterval))
                continue

    async def handleActiveDiameterPeers(self):
        """
        Prunes stale and duplicate entries from self.activePeers, and
        keeps the ActiveDiameterPeers key in Redis current.
        """

        # Flush the any pre-existing peers from Redis when this service is started.
        await(self.redisPeerMessaging.deleteQueue(queue=self.diameterPeerKey, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter'))

        while True:
            try:
                if not len(self.activePeers) > 0:
                    await(asyncio.sleep(1))
                    continue

                activeDiameterPeersTimeout = self.config.get('hss', {}).get('active_diameter_peers_timeout', 3600)

                activePeers = self.activePeers
                stalePeers = []
                diameterHosts = {}

                for key, connection in activePeers.items():
                    peerHostname = connection.Hostname
                    if peerHostname:
                        if peerHostname in diameterHosts:
                            diameterHosts[peerHostname].append(key)
                        else:
                            diameterHosts[peerHostname] = [key]

                for host in diameterHosts.values():
                    if len(host) > 1:
                        host.sort(key=lambda x: datetime.fromisoformat(activePeers[x].LastConnectTimestamp), reverse=True)
                        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [handleActiveDiameterPeers] Adding duplicate peers to stalePeers: {host[1:]}"))
                        stalePeers.extend(host[1:])

                for key, connection in activePeers.items():
                    isConnected = connection.Connected
                    if not isConnected: 
                        if (datetime.now(get_localzone()) - datetime.fromisoformat(connection.LastDisconnectTimestamp)).seconds > activeDiameterPeersTimeout:
                            stalePeers.append(key)
                
                if len(stalePeers) > 0:
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [handleActiveDiameterPeers] Pruning disconnected peers: {stalePeers}"))
                    try:
                        for key in stalePeers:
                            del self.activePeers[key]
                            result = await(self.redisPeerMessaging.deleteHashKey(name=self.diameterPeerKey, key=key, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter'))
                            await(self.logTool.logAsync(service='Diameter', level='error', message=f"{result}"))
                    except Exception as e:
                        await(self.logTool.logAsync(service='Diameter', level='warning', message=f"[Diameter] [handleActiveDiameterPeers] Error removing stale peer: {traceback.format_exc()}"))
                    await(self.logActivePeers())
                
                #Marshal the Peer objects and store in Redis
                for peerKey, peer in activePeers.items():
                    await(self.redisPeerMessaging.setHashValue(name=self.diameterPeerKey, key=peerKey, value=peer.model_dump_json(), keyExpiry=86400, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter'))

                await(asyncio.sleep(1))
            except Exception as e:
                await(self.logTool.logAsync(service='Diameter', level='warning', message=f"[Diameter] [handleActiveDiameterPeers] Exception: {traceback.format_exc()}"))
                await(asyncio.sleep(1))
                continue

    async def logActivePeers(self):
        """
        Logs the number of active connections on a rolling basis.
        """
        try:
            activePeers = self.activePeers
            if not len(activePeers) > 0:
                activePeers = ''

            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [logActivePeers] {len(self.activePeers)} Active Peers {activePeers}"))

            if isinstance(activePeers, dict):
                for peerKey, peerData in activePeers.items():
                    peerHost = peerData.Hostname
                    peerIsConnected = peerData.Connected
                    if peerHost and peerIsConnected:
                        if peerIsConnected:
                            await(self.redisPeerLogMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_connected_state',
                                    metricType='gauge', metricAction='set',
                                    metricLabels={'host': peerHost},
                                    metricValue=1.0, metricHelp='Connection state of diameter peers',
                                    metricExpiry=60,
                                    usePrefix=True,
                                    prefixHostname=self.hostname, 
                                    prefixServiceName='metric'))
                        else:
                            await(self.redisPeerLogMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_connected_state',
                                    metricType='gauge', metricAction='set',
                                    metricLabels={'host': peerHost},
                                    metricValue=0.0, metricHelp='Connection state of diameter peers',
                                    metricExpiry=60,
                                    usePrefix=True,
                                    prefixHostname=self.hostname, 
                                    prefixServiceName='metric'))
        except Exception as e:
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [logActivePeers] Exception: {traceback.format_exc()}"))

    async def logProcessedMessages(self):
        """
        Logs the number of processed messages on a rolling basis.
        """
        if not self.benchmarking:
            return False

        benchmarkInterval = int(self.benchmarkingInterval)

        while True:
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [logProcessedMessages] Processed {self.diameterRequests} inbound diameter messages in the last {self.benchmarkingInterval} second(s)"))
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [logProcessedMessages] Processed {self.diameterResponses} outbound in the last {self.benchmarkingInterval} second(s)"))
            await(self.redisMetricMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_request_count',
                                            metricType='gauge', metricAction='inc', 
                                            metricValue=float(self.diameterRequests),
                                            metricLabels={'benchmark_interval': self.benchmarkingInterval},
                                            metricHelp='Number of Diameter Requests Received',
                                            metricExpiry=60,
                                            usePrefix=True, 
                                            prefixHostname=self.hostname,
                                            prefixServiceName='metric'))
            await(self.redisMetricMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_response_count',
                                            metricType='gauge', metricAction='inc',
                                            metricLabels={'benchmark_interval': self.benchmarkingInterval},
                                            metricValue=float(self.diameterResponses), metricHelp='Number of Diameter Responses Sent',
                                            metricExpiry=60, 
                                            usePrefix=True,
                                            prefixHostname=self.hostname, 
                                            prefixServiceName='metric'))
            self.diameterRequests = 0
            self.diameterResponses = 0
            await(asyncio.sleep(benchmarkInterval))

    async def readInboundData(self, reader, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Reads incoming data from a connected client. Data is sent to a shared memory-based queue, to be polled and processed by a worker coroutine.
        Terminates the connection if the client disconnects, the queue fills or another exception occurs.
        """
        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [readInboundData] [{coroutineUuid}] New connection from {clientAddress} on port {clientPort}"))
        clientConnection = f"{clientAddress}-{clientPort}"
        while True:
            try:

                inboundData = await(asyncio.wait_for(reader.read(8192), timeout=socketTimeout))

                if reader.at_eof():
                    return False

                if len(inboundData) > 0:
                    inboundData = InboundData(SenderIp=clientAddress,
                                              SenderPort=clientPort,
                                              InitialReceiveTimestamp=time.time_ns(),
                                              InboundHex=inboundData.hex())
                    
                    self.sharedQueue.put_nowait(inboundData)

            except Exception as e:
                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Socket Exception for {clientAddress} on port {clientPort}, closing connection.\n{e}"))
                return False

    async def inboundDataWorker(self, coroutineUuid: str) -> bool:
        """
        Collects messages from the memory queue, performs peer validation and fires off to redis every 0.01 seconds.
        """
        batchInterval = 0.1
        inboundQueueName = f"diameter-inbound"
        while True:
            try:
                nextSendTime = time.time() + batchInterval
                messageList = []
                while time.time() < nextSendTime:
                    try:
                        inboundData = await(asyncio.wait_for(self.sharedQueue.get(), timeout=nextSendTime - time.time()))

                        if len(self.activePeers.get(f'{inboundData.SenderIp}-{inboundData.SenderPort}', {}).Metadata) == 0:
                            if not await(self.validateDiameterInbound(inboundData.SenderIp, inboundData.SenderPort, inboundData.InboundHex)):
                                await(self.logTool.logAsync(service='Diameter', level='warning', message=f"[Diameter] [inboundDataWorker] [{coroutineUuid}] Invalid Diameter Inbound, discarding data."))
                                continue
                            else:
                                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [inboundDataWorker] [{coroutineUuid}] Validated peer: {inboundData.SenderIp} on port {inboundData.SenderPort}"))

                        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [inboundDataWorker] [{coroutineUuid}] Queueing to redis: {inboundData}"))
                        messageList.append(inboundData.model_dump_json())
                        if self.benchmarking:
                            self.diameterRequests += 1
                    except asyncio.TimeoutError:
                        break

                if messageList:
                    await self.redisReaderMessaging.sendBulkMessage(queue=inboundQueueName, messageList=messageList, queueExpiry=self.diameterRequestTimeout, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')
                    messageList = []

            except Exception as e:
                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [inboundDataWorker] [{coroutineUuid}] Exception for inboundDataWorker, continuing.\n{e}"))
                pass

    async def writeOutboundData(self, writer, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Waits for a message to be received from Redis, then sends to the connected client.
        """
        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] writeOutboundData with host {clientAddress} on port {clientPort}"))
        while not writer.transport.is_closing():
            try:
                await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Waiting for messages for host {clientAddress} on port {clientPort}"))
                pendingOutboundMessage = (await(self.redisWriterMessaging.awaitMessage(key=f"diameter-outbound-{clientAddress}-{clientPort}", usePrefix=True, prefixHostname=self.hostname, prefixServiceName='diameter')))[1]
                outboundData = OutboundData.model_validate(pydantic_core.from_json(pendingOutboundMessage))
                diameterOutboundBinary = bytes.fromhex(outboundData.OutboundHex)
                await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Sending: {diameterOutboundBinary.hex()} to to {clientAddress} on {clientPort}."))

                writer.write(diameterOutboundBinary)
                await(writer.drain())
                if self.benchmarking:
                    self.diameterResponses += 1
            except Exception as e:
                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Connection closed for {clientAddress} on port {clientPort}, closing writer.{traceback.format_exc()}"))
                return False

    async def handleConnection(self, reader, writer):
        """
        For each new connection on port 3868, create an asynchronous reader and writer, and handle adding and updating self.activePeers.
        If a reader or writer returns false, ensure that the connection is torn down entirely.
        """
        try:
            coroutineUuid = str(uuid.uuid4())
            (clientAddress, clientPort) = writer.get_extra_info('peername')
            clientPort = str(clientPort)
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] New Connection from: {clientAddress} on port {clientPort}"))

            if f"{clientAddress}-{clientPort}" not in self.activePeers:
                activePeer = Peer(
                    IpAddress = clientAddress,
                    Port = clientPort,
                    Hostname = "",
                    Connected = True,
                    TransportProtocol = "",
                    PeerType = "",
                    LastConnectTimestamp = datetime.now(get_localzone()).isoformat('T'),
                    LastDisconnectTimestamp = "",
                    ReconnectionCount = 0,
                    Metadata = "",
                )

                self.activePeers[f"{clientAddress}-{clientPort}"] = activePeer
            else:
                activePeer = self.activePeers.get(f"{clientAddress}-{clientPort}", {})
                if activePeer:
                    reconnectionCount = activePeer.ReconnectionCount
                    reconnectionCount += 1
                    activePeer.ReconnectionCount = reconnectionCount

            self.activePeers[f"{clientAddress}-{clientPort}"].update(LastConnectTimestamp=datetime.now(get_localzone()).isoformat('T'),
                                                                     IpAddress=clientAddress,
                                                                     Port=clientPort,
                                                                     Connected=True)

            await(self.logActivePeers())

            readTask = asyncio.create_task(self.readInboundData(reader=reader, clientAddress=clientAddress, clientPort=clientPort, socketTimeout=self.socketTimeout, coroutineUuid=coroutineUuid))
            writeTask = asyncio.create_task(self.writeOutboundData(writer=writer, clientAddress=clientAddress, clientPort=clientPort, socketTimeout=self.socketTimeout, coroutineUuid=coroutineUuid))

            completeTasks, pendingTasks =  await(asyncio.wait([readTask, writeTask], return_when=asyncio.FIRST_COMPLETED))

            for pendingTask in pendingTasks:
                try:
                    pendingTask.cancel()
                    await(asyncio.sleep(0.1))
                except asyncio.CancelledError:
                    pass
      
            writer.close()
            await(writer.wait_closed())
            self.activePeers[f"{clientAddress}-{clientPort}"].update(LastDisconnectTimestamp=datetime.now(get_localzone()).isoformat('T'),
                                                                     Connected=False)
            
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [handleConnection] [{coroutineUuid}] Connection closed for {clientAddress} on port {clientPort}."))
            await(self.logActivePeers())
            return
        
        except Exception as e:
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [handleConnection] [{coroutineUuid}] Unhandled exception in diameterService.handleConnection: {e}"))
            return

    async def startServer(self, host: str=None, port: int=None, type: str=None):
        """
        Start a server with the given parameters and handle new clients with self.handleConnection.
        Also create a single instance of self.handleActiveDiameterPeers and self.logProcessedMessages.

        If self.useExternalSocketService is True, we'll only use this microservice to handle outbound DWRs and manage stored peers.
        """

        self.sharedQueue = asyncio.Queue(maxsize=1024)

        if self.enableOutboundDwr:
            handleOutboundDwrTask = asyncio.create_task(self.handleOutboundDwr())

        handleActiveDiameterPeerTask = asyncio.create_task(self.handleActiveDiameterPeers())

        if not self.useExternalSocketService:

            for i in range(self.workerPoolSize):
                asyncio.create_task(self.inboundDataWorker(coroutineUuid=f'inboundDataWorker-{i}'))

            if host is None:
                host=str(self.config.get('hss', {}).get('bind_ip', '0.0.0.0')[0])
            
            if port is None:
                port=int(self.config.get('hss', {}).get('bind_port', 3868))
            
            if type is None:
                type=str(self.config.get('hss', {}).get('transport', 'TCP'))

            self.socketTimeout = int(self.config.get('hss', {}).get('client_socket_timeout', 300))
            
            if self.benchmarking:
                logProcessedMessagesTask = asyncio.create_task(self.logProcessedMessages())

            if type.upper() == 'TCP':
                server = await(asyncio.start_server(self.handleConnection, host, port))
            elif type.upper() == 'SCTP':
                self.sctpSocket = sctp.sctpsocket_tcp(socket.AF_INET)
                self.sctpSocket.setblocking(False)
                self.sctpSocket.events.clear()
                self.sctpSocket.bind((host, port))
                self.sctpRtoInfo = self.sctpSocket.get_rtoinfo()
                self.sctpRtoMin = self.config.get('hss', {}).get('sctp', {}).get('rtoMin', 500)
                self.sctpRtoMax = self.config.get('hss', {}).get('sctp', {}).get('rtoMax', 5000)
                self.sctpRtoInitial = self.config.get('hss', {}).get('sctp', {}).get('rtoInitial', 1000)
                self.sctpRtoInfo.initial = int(self.sctpRtoInitial)
                self.sctpRtoInfo.max = int(self.sctpRtoMax)
                self.sctpRtoInfo.min = int(self.sctpRtoMin)
                self.sctpSocket.set_rtoinfo(self.sctpRtoInfo)
                self.sctpAssociatedParameters = self.sctpSocket.get_assocparams()
                sctpInitParameters = {
                    "initialRto": self.sctpRtoInfo.initial,
                    "rtoMin": self.sctpRtoInfo.min,
                    "rtoMax": self.sctpRtoInfo.max
                }
                self.sctpSocket.listen()
                await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [startServer] SCTP Parameters: {sctpInitParameters}"))

                server = await(asyncio.start_server(self.handleConnection, sock=self.sctpSocket))
            else:
                return False
            servingAddresses = ', '.join(str(sock.getsockname()) for sock in server.sockets)
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"{self.banners.diameterService()}\n[Diameter] Serving on {servingAddresses}"))
            async with server:
                await(server.serve_forever())


if __name__ == '__main__':
    diameterService = DiameterService()
    asyncio.run(diameterService.startServer())
