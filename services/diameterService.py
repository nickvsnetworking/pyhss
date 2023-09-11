import asyncio
import sys, os, json
import time, yaml, uuid
from datetime import datetime
sys.path.append(os.path.realpath('../lib'))
from messagingAsync import RedisMessagingAsync
from diameterAsync import DiameterAsync
from banners import Banners
from logtool import LogTool
import traceback

class DiameterService:
    """
    PyHSS Diameter Service
    A class for handling diameter inbounds and replies on Port 3868, via TCP.
    Functions in this class are high-performance, please edit with care. Last benchmarked on 24-08-2023.
    """

    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):
        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[Diameter] [__init__] Fatal Error - config.yaml not found, exiting.")
            quit()

        self.redisReaderMessaging = RedisMessagingAsync(host=redisHost, port=redisPort)
        self.redisWriterMessaging = RedisMessagingAsync(host=redisHost, port=redisPort)
        self.redisPeerMessaging = RedisMessagingAsync(host=redisHost, port=redisPort)
        self.banners = Banners()
        self.logTool = LogTool(config=self.config)
        self.diameterLibrary = DiameterAsync(logTool=self.logTool)
        self.activePeers = {}
        self.diameterRequestTimeout = int(self.config.get('hss', {}).get('diameter_request_timeout', 10))
        self.benchmarking = self.config.get('hss').get('enable_benchmarking', False)
    
    async def validateDiameterInbound(self, clientAddress: str, clientPort: str, inboundData) -> bool:
        """
        Asynchronously validates a given diameter inbound, and increments the 'Number of Diameter Inbounds' metric.
        """
        try:
            packetVars, avps = await(self.diameterLibrary.decodeDiameterPacket(inboundData))
            messageType = await(self.diameterLibrary.getDiameterMessageType(inboundData))
            originHost = (await self.diameterLibrary.getAvpData(avps, 264))[0]
            originHost = bytes.fromhex(originHost).decode("utf-8")
            peerType = await(self.diameterLibrary.getPeerType(originHost))
            self.activePeers[f"{clientAddress}-{clientPort}"].update({'lastDwrTimestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S") if messageType['inbound'] == 'DWR' else self.activePeers[f"{clientAddress}-{clientPort}"]['lastDwrTimestamp'], 
                                                                    'diameterHostname': originHost,
                                                                    'peerType': peerType,
                                                                    })
            await(self.redisReaderMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_inbound_count',
                                                metricType='counter', metricAction='inc', 
                                                metricValue=1.0, metricHelp='Number of Diameter Inbounds',
                                                metricLabels={
                                                "diameter_application_id": str(packetVars["ApplicationId"]),
                                                "diameter_cmd_code": str(packetVars["command_code"]),
                                                "endpoint": originHost,
                                                "type": "inbound"},
                                                metricExpiry=60))
        except Exception as e:
            await(self.logTool.logAsync(service='Diameter', level='warning', message=f"[Diameter] [validateDiameterInbound] Exception: {e}\n{traceback.format_exc()}"))
            return False
        return True

    async def handleActiveDiameterPeers(self):
        """
        Prunes stale entries from self.activePeers, and
        keeps the ActiveDiameterPeers key in Redis current.
        """
        while True:
            try:
                if not len(self.activePeers) > 0:
                    await(asyncio.sleep(0))
                    continue

                activeDiameterPeersTimeout = self.config.get('hss', {}).get('active_diameter_peers_timeout', 3600)

                stalePeers = []

                for key, connection in self.activePeers.items():
                    if connection.get('connectionStatus', '') == 'disconnected': 
                        if (datetime.now() - datetime.strptime(connection['disconnectTimestamp'], "%Y-%m-%d %H:%M:%S")).seconds > activeDiameterPeersTimeout:
                            stalePeers.append(key)
                
                if len(stalePeers) > 0:
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [handleActiveDiameterPeers] Pruning disconnected peers: {stalePeers}"))
                    for key in stalePeers:
                        del self.activePeers[key]
                    await(self.logActivePeers())
                
                await(self.redisPeerMessaging.setValue(key='ActiveDiameterPeers', value=json.dumps(self.activePeers), keyExpiry=86400))

                await(asyncio.sleep(1))
            except Exception as e:
                print(e)
                await(asyncio.sleep(1))
                continue

    async def logActivePeers(self):
        """
        Logs the number of active connections on a rolling basis.
        """
        activePeers = self.activePeers
        if not len(activePeers) > 0:
            activePeers = ''
        await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [logActivePeers] {len(self.activePeers)} Active Peers {activePeers}"))

    async def readInboundData(self, reader, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Reads and parses incoming data from a connected client. Validated diameter messages are sent to the redis queue for processing.
        Terminates the connection if diameter traffic is not received, or if the client disconnects.
        """
        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [readInboundData] [{coroutineUuid}] New connection from {clientAddress} on port {clientPort}"))
        while True:
            try:

                inboundData = await(asyncio.wait_for(reader.read(8192), timeout=socketTimeout))

                if self.benchmarking:
                    startTime = time.perf_counter()

                if reader.at_eof():
                    await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Socket Timeout for {clientAddress} on port {clientPort}, closing connection."))
                    return False
                
                if len(inboundData) > 0:
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Received data from {clientAddress} on port {clientPort}"))
                    
                    if self.benchmarking:
                        diamteterValidationStartTime = time.perf_counter()
                    if not await(self.validateDiameterInbound(clientAddress, clientPort, inboundData)):
                        await(self.logTool.logAsync(service='Diameter', level='warning', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Invalid Diameter Inbound, discarding data."))
                        await(asyncio.sleep(0))
                        continue
                    if self.benchmarking:
                        await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Time taken to validate diameter request: {round(((time.perf_counter() - diamteterValidationStartTime)*1000), 3)} ms"))
                        

                    diameterMessageType = await(self.diameterLibrary.getDiameterMessageType(binaryData=inboundData))
                    diameterMessageType = diameterMessageType.get('inbound', '')

                    inboundQueueName = f"diameter-inbound-{clientAddress}-{clientPort}-{time.time_ns()}"
                    inboundHexString = json.dumps({f"diameter-inbound": inboundData.hex()})
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [readInboundData] [{coroutineUuid}] [{diameterMessageType}] Queueing {inboundHexString}"))
                    await(self.redisReaderMessaging.sendMessage(queue=inboundQueueName, message=inboundHexString, queueExpiry=self.diameterRequestTimeout))
                    if self.benchmarking:
                        await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Time taken to process request: {round(((time.perf_counter() - startTime)*1000), 3)} ms"))
                    await(asyncio.sleep(0))
                        
            except Exception as e:
                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Socket Exception for {clientAddress} on port {clientPort}, closing connection.\n{e}"))
                return False

    async def writeOutboundData(self, writer, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Continually polls the Redis queue for outbound messages. Received messages from the queue are validated against the connected client, and sent.
        """
        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] writeOutboundData with host {clientAddress} on port {clientPort}"))
        while True:
            try:
                if self.benchmarking:
                    startTime = time.perf_counter()

                if writer.transport.is_closing():
                    return False
                
                pendingOutboundQueue = await(self.redisWriterMessaging.getNextQueue(pattern=f'diameter-outbound-{clientAddress.replace(".", "*")}-{clientPort}-*'))
                if not len(pendingOutboundQueue) > 0:
                    await(asyncio.sleep(0))
                    continue
                pendingOutboundQueue = pendingOutboundQueue.decode()

                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Pending Outbound Queue: {pendingOutboundQueue}"))
                outboundQueueSplit = str(pendingOutboundQueue).split('-')
                queuedMessageType = outboundQueueSplit[1]
                diameterOutboundHost = outboundQueueSplit[2]
                diameterOutboundPort = outboundQueueSplit[3]

                if str(diameterOutboundHost) == str(clientAddress) and str(diameterOutboundPort) == str(clientPort) and queuedMessageType == 'outbound':
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Matched {pendingOutboundQueue} to host {clientAddress} on port {clientPort}"))
                    diameterOutbound = json.loads(await(self.redisWriterMessaging.getMessage(queue=pendingOutboundQueue)))
                    diameterOutboundBinary = bytes.fromhex(next(iter(diameterOutbound.values())))
                    diameterMessageType = await(self.diameterLibrary.getDiameterMessageType(binaryData=diameterOutboundBinary))
                    diameterMessageType = diameterMessageType.get('outbound', '')
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] [{diameterMessageType}] Sending: {diameterOutboundBinary.hex()} to to {clientAddress} on {clientPort}."))
                    writer.write(diameterOutboundBinary)
                    await(writer.drain())
                    await(asyncio.sleep(0))
                    if self.benchmarking:
                        await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Time taken to write response: {round(((time.perf_counter() - startTime)*1000), 3)} ms"))

            except Exception:
                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Connection closed for {clientAddress} on port {clientPort}, closing writer."))
                return False
            await(asyncio.sleep(0))

    async def handleConnection(self, reader, writer):
        """
        For each new connection on port 3868, create an asynchronous reader and writer, and handle adding and updating self.activePeers.
        If a reader or writer returns false, ensure that the connection is torn down entirely.
        """
        try:
            coroutineUuid = str(uuid.uuid4())
            (clientAddress, clientPort) = writer.get_extra_info('peername')
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] New Connection from: {clientAddress} on port {clientPort}"))
            if f"{clientAddress}-{clientPort}" not in self.activePeers:
                self.activePeers[f"{clientAddress}-{clientPort}"] = {
                                                                        "connectTimestamp": '',
                                                                        "disconnectTimestamp": '',
                                                                        "reconnectionCount": 0,
                                                                        "ipAddress":'',
                                                                        "port":'',
                                                                        "connectionStatus": '',
                                                                        "lastDwrTimestamp": '',
                                                                        "diameterHostname": '',
                                                                        "peerType": '',
                                                                        }
            else:
                reconnectionCount = self.activePeers.get(f"{clientAddress}-{clientPort}", {}).get('reconnectionCount', 0)
                reconnectionCount += 1
                self.activePeers[f"{clientAddress}-{clientPort}"].update({
                                                                        "reconnectionCount": reconnectionCount
                                                                        })

            self.activePeers[f"{clientAddress}-{clientPort}"].update({                
                                                                    "connectTimestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                                                    "ipAddress":clientAddress,
                                                                    "port": clientPort,
                                                                    "connectionStatus": 'connected',
                                                                    })
            await(self.logActivePeers())

            readTask = asyncio.create_task(self.readInboundData(reader=reader, clientAddress=clientAddress, clientPort=clientPort, socketTimeout=self.socketTimeout, coroutineUuid=coroutineUuid))
            writeTask = asyncio.create_task(self.writeOutboundData(writer=writer, clientAddress=clientAddress, clientPort=clientPort, socketTimeout=self.socketTimeout, coroutineUuid=coroutineUuid))

            completeTasks, pendingTasks =  await(asyncio.wait([readTask, writeTask], return_when=asyncio.FIRST_COMPLETED))

            for pendingTask in pendingTasks:
                try:
                    pendingTask.cancel()
                    await(asyncio.sleep(0))
                except asyncio.CancelledError:
                    pass
      
            writer.close()
            await(writer.wait_closed())
            self.activePeers[f"{clientAddress}-{clientPort}"].update({
                                                                    "connectionStatus": 'disconnected',
                                                                    "disconnectTimestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                                                    })
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [handleConnection] [{coroutineUuid}] Connection closed for {clientAddress} on port {clientPort}."))
            await(self.logActivePeers())
            return
        
        except Exception as e:
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [handleConnection] [{coroutineUuid}] Unhandled exception in diameterService.handleConnection: {e}"))
            return

    async def startServer(self, host: str=None, port: int=None, type: str=None):
        """
        Start a server with the given parameters and handle new clients with self.handleConnection.
        Also create a single instance of self.handleActiveDiameterPeers.
        """

        if host is None:
            host=str(self.config.get('hss', {}).get('bind_ip', '0.0.0.0')[0])
        
        if port is None:
            port=int(self.config.get('hss', {}).get('bind_port', 3868))
        
        if type is None:
            type=str(self.config.get('hss', {}).get('transport', 'TCP'))

        self.socketTimeout = int(self.config.get('hss', {}).get('client_socket_timeout', 300))

        if type.upper() == 'TCP':
            server = await(asyncio.start_server(self.handleConnection, host, port))
        else:
            return False
        servingAddresses = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        await(self.logTool.logAsync(service='Diameter', level='info', message=f"{self.banners.diameterService()}\n[Diameter] Serving on {servingAddresses}"))
        handleActiveDiameterPeerTask = asyncio.create_task(self.handleActiveDiameterPeers())

        async with server:
            await(server.serve_forever())


if __name__ == '__main__':
    diameterService = DiameterService()
    asyncio.run(diameterService.startServer())