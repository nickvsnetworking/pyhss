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

        self.redisMessaging = RedisMessagingAsync(host=redisHost, port=redisPort)
        self.banners = Banners()
        self.logTool = LogTool(config=self.config)
        self.diameterLibrary = DiameterAsync()
        self.activeConnections = {}
    
    async def validateDiameterInbound(self, clientAddress: str, clientPort: str, inboundData) -> bool:
        """
        Asynchronously validates a given diameter inbound, and increments the 'Number of Diameter Inbounds' metric.
        """
        try:
            packetVars, avps = await(self.diameterLibrary.decodeDiameterPacketAsync(inboundData))
            messageType = await(self.diameterLibrary.getDiameterMessageTypeAsync(inboundData))
            originHost = (await self.diameterLibrary.getAvpDataAsync(avps, 264))[0]
            originHost = bytes.fromhex(originHost).decode("utf-8")
            self.activeConnections[f"{clientAddress}-{clientPort}"].update({'last_dwr_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S") if messageType['inbound'] == 'DWR' else self.activeConnections[f"{clientAddress}:{clientPort}"]['last_dwr_timestamp'], 
                                                              'DiameterHostname': originHost,
                                                              })
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

    async def handleActiveDiameterPeers(self):
        """
        Prunes stale connection entries from self.activeConnections.
        """
        while True:
            try:
                if not len(self.activeConnections) > 0:
                    await(asyncio.sleep(1))
                    continue

                activeDiameterPeersTimeout = self.config.get('hss', {}).get('active_diameter_peers_timeout', 86400)

                for key, connection in self.activeConnections.items():
                    if connection.get('connection_status', '') == 'disconnected':
                        if (datetime.now() - datetime.strptime(connection['connect_timestamp'], "%Y-%m-%d %H:%M:%S")).seconds > activeDiameterPeersTimeout:
                            del self.activeConnections[key]
                
                await(self.redisMessaging.sendMessage(queue='ActiveDiameterPeers', message=json.dumps(self.activeConnections)))

                await(asyncio.sleep(1))
            except Exception as e:
                print(e)
                await(asyncio.sleep(1))
                continue

    async def logActiveConnections(self):
        """
        Logs the number of active connections on a rolling basis.
        """
        activeConnections = self.activeConnections
        if not len(activeConnections) > 0:
            activeConnections = ''
        await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [logActiveConnections] {len(self.activeConnections)} Active Connections {activeConnections}", redisClient=self.redisMessaging))

    async def readInboundData(self, reader, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Reads and parses incoming data from a connected client. Validated diameter messages are sent to the redis queue for processing.
        Terminates the connection if diameter traffic is not received, or if the client disconnects.
        """
        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [readInboundData] [{coroutineUuid}] New connection from {clientAddress} on port {clientPort}", redisClient=self.redisMessaging))
        while True:
            try:

                inboundData = await(asyncio.wait_for(reader.read(1024), timeout=socketTimeout))

                if reader.at_eof():
                    await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Socket Timeout for {clientAddress} on port {clientPort}, closing connection.", redisClient=self.redisMessaging))
                    return False
                
                if len(inboundData) > 0:
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Received data from {clientAddress} on port {clientPort}", redisClient=self.redisMessaging))
                    
                    if not await(self.validateDiameterInbound(clientAddress, clientPort, inboundData)):
                        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Invalid Diameter Inbound, terminating connection.", redisClient=self.redisMessaging))
                        return False
                    
                    diameterMessageType = await(self.diameterLibrary.getDiameterMessageTypeAsync(binaryData=inboundData))
                    diameterMessageType = diameterMessageType.get('inbound', '')

                    inboundQueueName = f"diameter-inbound-{clientAddress}-{clientPort}-{time.time_ns()}"
                    inboundHexString = json.dumps({f"diameter-inbound": inboundData.hex()})
                    await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [readInboundData] [{coroutineUuid}] [{diameterMessageType}] Queueing {inboundHexString}", redisClient=self.redisMessaging))
                    asyncio.ensure_future(self.redisMessaging.sendMessage(queue=inboundQueueName, message=inboundHexString, queueExpiry=60))

            except Exception as e:
                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [readInboundData] [{coroutineUuid}] Socket Exception for {clientAddress} on port {clientPort}, closing connection.\n{e}", redisClient=self.redisMessaging))
                return False

    async def writeOutboundData(self, writer, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Continually polls the Redis queue for outbound messages. Received messages from the queue are validated against the connected client, and sent.
        """
        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] writeOutboundData with host {clientAddress} on port {clientPort}", redisClient=self.redisMessaging))
        while True:
            try:

                if writer.transport.is_closing():
                    return False
                
                pendingOutboundQueues = await(self.redisMessaging.getQueues(pattern='diameter-outbound*'))
                if not len(pendingOutboundQueues) > 0:
                    await(asyncio.sleep(0))
                    continue
                await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Pending Outbound Queues: {pendingOutboundQueues}", redisClient=self.redisMessaging))
                for outboundQueue in pendingOutboundQueues:
                    outboundQueueSplit = str(outboundQueue).split('-')
                    queuedMessageType = outboundQueueSplit[1]
                    diameterOutboundHost = outboundQueueSplit[2]
                    diameterOutboundPort = outboundQueueSplit[3]

                    if str(diameterOutboundHost) == str(clientAddress) and str(diameterOutboundPort) == str(clientPort) and queuedMessageType == 'outbound':
                        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Matched {outboundQueue} to host {clientAddress} on port {clientPort}", redisClient=self.redisMessaging))
                        diameterOutbound = json.loads(await(self.redisMessaging.getMessage(queue=outboundQueue)))
                        diameterOutboundBinary = bytes.fromhex(next(iter(diameterOutbound.values())))
                        diameterMessageType = await(self.diameterLibrary.getDiameterMessageTypeAsync(binaryData=diameterOutboundBinary))
                        diameterMessageType = diameterMessageType.get('outbound', '')
                        await(self.logTool.logAsync(service='Diameter', level='debug', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] [{diameterMessageType}] Sending: {diameterOutboundBinary.hex()} to to {clientAddress} on {clientPort}.", redisClient=self.redisMessaging))
                        writer.write(diameterOutboundBinary)
                        await(writer.drain())
                        await(asyncio.sleep(0))

            except Exception:
                await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [writeOutboundData] [{coroutineUuid}] Connection closed for {clientAddress} on port {clientPort}, closing writer.", redisClient=self.redisMessaging))
                return False
            await(asyncio.sleep(0))

    async def handleConnection(self, reader, writer):
        """
        For each new connection on port 3868, create an asynchronous reader and writer. If a reader or writer returns false, ensure that the connection is torn down entirely.
        """
        try:
            coroutineUuid = str(uuid.uuid4())
            (clientAddress, clientPort) = writer.get_extra_info('peername')
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] New Connection from: {clientAddress} on port {clientPort}", redisClient=self.redisMessaging))
            if f"{clientAddress}-{clientPort}" not in self.activeConnections:
                self.activeConnections[f"{clientAddress}-{clientPort}"] = {}
            self.activeConnections[f"{clientAddress}-{clientPort}"].update({                
                                                                    "connect_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                                                    "recv_ip_address":clientAddress,
                                                                    "recv_ip_port":clientAddress,
                                                                    "connection_status": 'connected',
                                                                    })
            await(self.logActiveConnections())

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
            self.activeConnections[f"{clientAddress}-{clientPort}"].update({
                                                                    "connection_status": 'disconnected',
                                                                    })
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [handleConnection] [{coroutineUuid}] Connection closed for {clientAddress} on port {clientPort}.", redisClient=self.redisMessaging))
            await(self.logActiveConnections())
            return
        
        except Exception as e:
            await(self.logTool.logAsync(service='Diameter', level='info', message=f"[Diameter] [handleConnection] [{coroutineUuid}] Unhandled exception in diameterService.handleConnection: {e}\n{traceback.format_exc()}", redisClient=self.redisMessaging))
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
        await(self.logTool.logAsync(service='Diameter', level='info', message=f"{self.banners.diameterService()}\n[Diameter] Serving on {servingAddresses}", redisClient=self.redisMessaging))
        handleActiveDiameterPeerTask = asyncio.create_task(self.handleActiveDiameterPeers())

        async with server:
            await(server.serve_forever())


if __name__ == '__main__':
    diameterService = DiameterService()
    asyncio.run(diameterService.startServer(), debug=True)