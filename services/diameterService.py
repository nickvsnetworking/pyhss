import asyncio
import sctp, socket
import sys, os, json
import time, yaml, uuid
sys.path.append(os.path.realpath('../lib'))
from messagingAsync import RedisMessagingAsync
from diameter import Diameter
from banners import Banners
from logtool import LogTool

class DiameterService:
    """
    PyHSS Diameter Service
    A class for handling diameter requests and replies on Port 3868, via TCP or SCTP.
    Functions in this class are high-performance, please edit with care. Last benchmarked on 23-08-2023.
    """

    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):
        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[Diameter] [__init__] Fatal Error - config.yaml not found, exiting.")
            quit()

        self.redisMessaging = RedisMessagingAsync(host=redisHost, port=redisPort)
        self.diameterLibrary = Diameter()
        self.banners = Banners()
        self.logTool = LogTool()
        self.diameterLogger = self.logTool.setupLogger(loggerName='Diameter', config=self.config)
        self.socketTimeout = int(self.config.get('hss', {}).get('client_socket_timeout', 300))

    async def validateDiameterRequest(self, requestData) -> bool:
        """
        Asynchronously validates a given diameter request, and increments the 'Number of Diameter Requests' metric.
        """
        try:
            packetVars, avps = self.diameterLibrary.decode_diameter_packet(requestData)
            originHost = self.diameterLibrary.get_avp_data(avps, 264)[0]
            originHost = bytes.fromhex(originHost).decode("utf-8")
            asyncio.ensure_future(self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_request_count',
                                                metricType='counter', metricAction='inc', 
                                                metricValue=1.0, metricHelp='Number of Diameter Requests',
                                                metricLabels={
                                                "diameter_application_id": str(packetVars["ApplicationId"]),
                                                "diameter_cmd_code": str(packetVars["command_code"]),
                                                "endpoint": originHost,
                                                "type": "request"},
                                                metricExpiry=60))
        except Exception as e:
            return False
        return True
    
    async def readRequestData(self, reader, clientAddress: str, clientPort: str, socketTimeout: int, coroutineUuid: str) -> bool:
        """
        Reads and parses incoming data from a connected client. Terminates the connection if diameter traffic is not received.
        """
        self.diameterLogger.info(f"[Diameter] [readRequestData] [{coroutineUuid}] New connection from {clientAddress} on port {clientPort}")
        while True:
            try:
                requestData = await asyncio.wait_for(reader.read(1024), timeout=socketTimeout)
                if len(requestData) > 0:
                    self.diameterLogger.debug(f"[Diameter] [readRequestData] [{coroutineUuid}] Received data from {clientAddress} on port {clientPort}")
                    
                    if not await(self.validateDiameterRequest(requestData)):
                        self.diameterLogger.debug(f"[Diameter] [readRequestData] [{coroutineUuid}] Invalid Diameter Request, terminating connection.")
                        return False

                    requestQueueName = f"diameter-request-{clientAddress}-{clientPort}-{time.time_ns()}"
                    requestHexString = json.dumps({f"diameter-request": requestData.hex()})
                    self.diameterLogger.debug(f"[Diameter] [readRequestData] [{coroutineUuid}] Queueing {requestHexString}")
                    asyncio.ensure_future(self.redisMessaging.sendMessage(queue=requestQueueName, message=requestHexString, queueExpiry=60))
            except asyncio.TimeoutError:
                self.diameterLogger.info(f"[Diameter] [readRequestData] [{coroutineUuid}] Socket Timeout for {clientAddress} on port {clientPort}, closing connection.")
                return False

    async def writeResponseData(self, writer, clientAddress: str, clientPort: str, coroutineUuid: str) -> bool:
        self.diameterLogger.debug(f"[Diameter] [writeResponseData] [{coroutineUuid}] writeResponseData with host {clientAddress} on port {clientPort}")
        while True:
            try:
                pendingResponseQueues = await(self.redisMessaging.getQueues())
                if not len(pendingResponseQueues) > 0:
                    assert()
                for responseQueue in pendingResponseQueues:
                    responseQueueSplit = str(responseQueue).split('-')
                    queuedMessageType = responseQueueSplit[1]
                    diameterResponseHost = responseQueueSplit[2]
                    diameterResponsePort = responseQueueSplit[3]
                    if str(diameterResponseHost) == str(clientAddress) and str(diameterResponsePort) == str(clientPort) and queuedMessageType == 'response':
                        self.diameterLogger.debug(f"[Diameter] [writeResponseData] [{coroutineUuid}] Matched {responseQueue} to host {clientAddress} on port {clientPort}")
                        try:
                            diameterResponse = json.loads(await(self.redisMessaging.getMessage(queue=responseQueue)))
                            self.diameterLogger.debug(f"[Diameter] [writeResponseData] [{coroutineUuid}] Attempting to send outbound response to {clientAddress} on {clientPort}.")
                            diameterResponseBinary = bytes.fromhex(next(iter(diameterResponse.values())))
                            self.diameterLogger.debug(f"[Diameter] [writeResponseData] [{coroutineUuid}] Sending: {diameterResponseBinary.hex()} to to {clientAddress} on {clientPort}.")
                            writer.write(diameterResponseBinary)
                            await writer.drain()
                        except Exception as e:
                            print(e)
            except ConnectionError:
                self.diameterLogger.info(f"[Diameter] [writeResponseData] [{coroutineUuid}] Connection closed for {clientAddress} on port {clientPort}, closing writer.")
                return False
            except Exception as e:
                continue

    async def handleConnection(self, reader, writer):
        (clientAddress, clientPort) = writer.get_extra_info('peername')
        self.diameterLogger.debug(f"[Diameter] Initial Connection from: {clientAddress} on port {clientPort}")
        coroutineUuid = uuid.uuid4()

        if False in await asyncio.gather(self.readRequestData(reader=reader, clientAddress=clientAddress, clientPort=clientPort, socketTimeout=self.socketTimeout, coroutineUuid=coroutineUuid), 
                                         self.writeResponseData(writer=writer, clientAddress=clientAddress, clientPort=clientPort, coroutineUuid=coroutineUuid)):
            self.diameterLogger.debug(f"[Diameter] Closing Writer for {clientAddress} on port {clientPort}.")
            writer.close()
            await writer.wait_closed()
            self.diameterLogger.debug(f"[Diameter] Closed Writer for {clientAddress} on port {clientPort}.")
            return

    async def startServer(self, host: str='0.0.0.0', port: int=3868, type: str='TCP'):
        if type.upper() == 'TCP':
            server = await asyncio.start_server(self.handleConnection, host, port)
        elif type.upper() == 'SCTP':
            sctpSocket = sctp.sctpsocket_tcp(socket.AF_INET)
            server = await asyncio.start_server(self.handleConnection, host, port, socket=sctpSocket)
        else:
            return False
        servingAddresses = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        self.diameterLogger.info(self.banners.diameterService())
        self.diameterLogger.info(f'[Diameter] Serving on {servingAddresses}')
            
        async with server:
            await server.serve_forever()


if __name__ == '__main__':
    diameterService = DiameterService()
    asyncio.run(diameterService.startServer())