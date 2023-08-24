import asyncio
import sys, os, json
import time, yaml, uuid
sys.path.append(os.path.realpath('../lib'))
from messagingAsync import RedisMessagingAsync
from diameterAsync import DiameterAsync
from banners import Banners
from logtool import LogTool

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

        self.redisMessaging = RedisMessagingAsync(host=redisHost, port=redisPort)
        self.banners = Banners()
        self.logTool = LogTool()
        self.diameterLogger = self.logTool.setupLogger(loggerName='Diameter', config=self.config)
        self.diameterLibrary = DiameterAsync(logger=self.diameterLogger)
        self.activeConnections = set()

    async def validateDiameterInbound(self, inboundData) -> bool:
        """
        Asynchronously validates a given diameter inbound, and increments the 'Number of Diameter Inbounds' metric.
        """
        try:
            packetVars, avps = await(self.diameterLibrary.decodeDiameterPacketAsync(inboundData))
            originHost = (await self.diameterLibrary.getAvpDataAsync(avps, 264))[0]
            originHost = bytes.fromhex(originHost).decode("utf-8")
            asyncio.ensure_future(self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_inbound_count',
                                                metricType='counter', metricAction='inc', 
                                                metricValue=1.0, metricHelp='Number of Diameter Inbounds',
                                                metricLabels={
                                                "diameter_application_id": str(packetVars["ApplicationId"]),
                                                "diameter_cmd_code": str(packetVars["command_code"]),
                                                "endpoint": originHost,
                                                "type": "inbound"},
                                                metricExpiry=60))
        except Exception as e:
            print(e)
            return False
        return True
    
    async def logActiveConnections(self):
        """
        Logs the number of active connections on a rolling basis.
        """
        while True:
            activeConnections = self.activeConnections
            if not len(activeConnections) > 0:
                activeConnections = ''
            self.diameterLogger.info(f"[Diameter] [logActiveConnections] {len(self.activeConnections)} Active Connections {activeConnections}")
            await(asyncio.sleep(60))
    
    async def readInboundData(self, reader, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Reads and parses incoming data from a connected client. Validated diameter messages are sent to the redis queue for processing.
        Terminates the connection if diameter traffic is not received, or if the client disconnects.
        """
        self.diameterLogger.info(f"[Diameter] [readInboundData] [{coroutineUuid}] New connection from {clientAddress} on port {clientPort}")
        while True:
            try:

                inboundData = await(asyncio.wait_for(reader.read(1024), timeout=socketTimeout))

                if reader.at_eof():
                    return False
                
                if len(inboundData) > 0:
                    self.diameterLogger.debug(f"[Diameter] [readInboundData] [{coroutineUuid}] Received data from {clientAddress} on port {clientPort}")
                    
                    if not await(self.validateDiameterInbound(inboundData)):
                        self.diameterLogger.debug(f"[Diameter] [readInboundData] [{coroutineUuid}] Invalid Diameter Inbound, terminating connection.")
                        return False
                    
                    diameterMessageType = await(self.diameterLibrary.getDiameterMessageTypeAsync(binaryData=inboundData))
                    diameterMessageType = diameterMessageType.get('inbound', '')

                    inboundQueueName = f"diameter-inbound-{clientAddress}-{clientPort}-{time.time_ns()}"
                    inboundHexString = json.dumps({f"diameter-inbound": inboundData.hex()})
                    self.diameterLogger.debug(f"[Diameter] [readInboundData] [{coroutineUuid}] [{diameterMessageType}] Queueing {inboundHexString}")
                    asyncio.ensure_future(self.redisMessaging.sendMessage(queue=inboundQueueName, message=inboundHexString, queueExpiry=60))

            except Exception as e:
                self.diameterLogger.info(f"[Diameter] [readInboundData] [{coroutineUuid}] Socket Timeout for {clientAddress} on port {clientPort}, closing connection.")
                self.diameterLogger.debug(e)
                return False

    async def writeOutboundData(self, writer, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Continually polls the Redis queue for outbound messages. Received messages from the queue are validated against the connected client, and sent.
        """
        self.diameterLogger.debug(f"[Diameter] [writeOutboundData] [{coroutineUuid}] writeOutboundData with host {clientAddress} on port {clientPort}")
        while True:
            try:

                if writer.transport.is_closing():
                    return False
                
                pendingOutboundQueues = await(self.redisMessaging.getQueues(pattern='diameter-outbound*'))
                if not len(pendingOutboundQueues) > 0:
                    await(asyncio.sleep(0))
                    continue

                self.diameterLogger.debug(f"[Diameter] [writeOutboundData] [{coroutineUuid}] Pending Outbound Queues: {pendingOutboundQueues}")
                for outboundQueue in pendingOutboundQueues:
                    outboundQueueSplit = str(outboundQueue).split('-')
                    queuedMessageType = outboundQueueSplit[1]
                    diameterOutboundHost = outboundQueueSplit[2]
                    diameterOutboundPort = outboundQueueSplit[3]

                    if str(diameterOutboundHost) == str(clientAddress) and str(diameterOutboundPort) == str(clientPort) and queuedMessageType == 'outbound':
                        self.diameterLogger.debug(f"[Diameter] [writeOutboundData] [{coroutineUuid}] Matched {outboundQueue} to host {clientAddress} on port {clientPort}")
                        diameterOutbound = json.loads(await(self.redisMessaging.getMessage(queue=outboundQueue)))
                        diameterOutboundBinary = bytes.fromhex(next(iter(diameterOutbound.values())))
                        diameterMessageType = await(self.diameterLibrary.getDiameterMessageTypeAsync(binaryData=diameterOutboundBinary))
                        diameterMessageType = diameterMessageType.get('outbound', '')
                        self.diameterLogger.debug(f"[Diameter] [writeOutboundData] [{coroutineUuid}] [{diameterMessageType}] Sending: {diameterOutboundBinary.hex()} to to {clientAddress} on {clientPort}.")
                        writer.write(diameterOutboundBinary)
                        await(writer.drain())
                        await(asyncio.sleep(0))

            except Exception:
                self.diameterLogger.info(f"[Diameter] [writeOutboundData] [{coroutineUuid}] Connection closed for {clientAddress} on port {clientPort}, closing writer.")
                return False
            await(asyncio.sleep(0))

    async def handleConnection(self, reader, writer):
        """
        For each new connection on port 3868, create an asynchronous reader and writer. If a reader or writer returns false, ensure that the connection is torn down entirely.
        """
        try:
            (clientAddress, clientPort) = writer.get_extra_info('peername')
            self.diameterLogger.debug(f"[Diameter] Initial Connection from: {clientAddress} on port {clientPort}")
            coroutineUuid = str(uuid.uuid4())
            self.activeConnections.add((clientAddress, clientPort, coroutineUuid))

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
            self.activeConnections.discard((clientAddress, clientPort, coroutineUuid))

            return
        
        except Exception as e:
            self.diameterLogger.warning(f"[Diameter] [handleConnection] [{coroutineUuid}] Unhandled exception in diameterService.handleConnection: {e}")
            return

    async def startServer(self, host: str=None, port: int=None, type: str=None):
        """
        Start a server with the given parameters and handle new clients with self.handleConnection.
        Also create a single instance of self.logActiveConnections.
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
        self.diameterLogger.info(self.banners.diameterService())
        self.diameterLogger.info(f'[Diameter] Serving on {servingAddresses}')
        asyncio.create_task(self.logActiveConnections())

        async with server:
            await(server.serve_forever())


if __name__ == '__main__':
    diameterService = DiameterService()
    asyncio.run(diameterService.startServer(), debug=True)