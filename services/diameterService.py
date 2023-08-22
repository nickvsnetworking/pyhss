import asyncio
import sctp, socket
import sys, os, json
import time, yaml
sys.path.append(os.path.realpath('../lib'))
from messagingAsync import RedisMessagingAsync
from diameter import Diameter
from banners import Banners
from logtool import LogTool

class DiameterService:
    """
    PyHSS Diameter Service
    A class for handling diameter requests and replies on Port 3868, via TCP or SCTP.
    """

    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):
        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[Diameter] Fatal Error - config.yaml not found, exiting.")
            quit()

        self.redisMessaging = RedisMessagingAsync(host=redisHost, port=redisPort)
        self.diameterLibrary = Diameter()
        self.banners = Banners()
        self.logTool = LogTool()
        self.diameterLogger = self.logTool.setupLogger(loggerName='Diameter', config=self.config)
        self.socketTimeout = int(self.config.get('hss', {}).get('client_socket_timeout', 300))

    def validateDiameterRequest(self, requestData) -> bool:
        try:
            packetVars, avps = self.diameterLibrary.decode_diameter_packet(requestData)
            originHost = self.diameterLibrary.get_avp_data(avps, 264)[0]
            originHost = bytes.fromhex(originHost).decode("utf-8")
        except Exception as e:
            return False
        return True
    
    async def readRequestData(self, reader, clientAddress: str, clientPort: str, socketTimeout: int) -> bool:
        self.diameterLogger.info(f"[Diameter] New connection from {clientAddress} on port {clientPort}")

        while True:
            try:
                requestData = await asyncio.wait_for(reader.read(1024), timeout=socketTimeout)
                if len(requestData) > 0:
                    self.diameterLogger.debug(f"[Diameter] Received data from {clientAddress} on port {clientPort}")
                    
                    if not self.validateDiameterRequest(requestData):
                        self.diameterLogger.debug(f"[Diameter] Invalid Diameter Request, terminating connection.")
                        return False

                    requestQueueName = f"diameter-request-{clientAddress}-{clientPort}-{time.time_ns()}"
                    requestHexString = json.dumps({f"diameter-request": requestData.hex()})
                    self.diameterLogger.debug(f"[Diameter] Queueing {requestHexString}")
                    await(self.redisMessaging.sendMessage(queue=requestQueueName, message=requestHexString))
            except asyncio.TimeoutError:
                self.diameterLogger.info(f"[Diameter] Socket Timeout for {clientAddress} on port {clientPort}, closing connection.")
                return False

    async def writeResponseData(self, writer, clientAddress: str, clientPort: str) -> bool:
        self.diameterLogger.debug(f"[Diameter] writeResponseData with host {clientAddress} on port {clientPort}")
        while True:
            try:
                pendingResponseQueues = await(self.redisMessaging.getQueues())
                if not len(pendingResponseQueues) > 0:
                    assert()
                for responseQueue in pendingResponseQueues:
                    queuedMessageType = str(responseQueue).split('-')[1]
                    diameterResponseHost = str(responseQueue).split('-')[2]
                    diameterResponsePort = str(responseQueue).split('-')[3]
                    if str(diameterResponseHost) == str(clientAddress) and str(diameterResponsePort) == str(clientPort) and queuedMessageType == 'response':
                        self.diameterLogger.debug(f"[Diameter] Matched {responseQueue} to host {clientAddress} on port {clientPort}")
                        try:
                            diameterResponse = json.loads(await(self.redisMessaging.getMessage(queue=responseQueue)))
                            self.diameterLogger.debug(f"[Diameter] Attempting to send outbound response to {clientAddress} on {clientPort}.")
                            diameterResponseBinary = bytes.fromhex(next(iter(diameterResponse.values())))
                            self.diameterLogger.debug(f"[Diameter] Sending: {diameterResponseBinary.hex()} to to {clientAddress} on {clientPort}.")
                            writer.write(diameterResponseBinary)
                            await writer.drain()
                        except Exception as e:
                            print(e)
            except ConnectionError:
                self.diameterLogger.info(f"[Diameter] Connection closed for {clientAddress} on port {clientPort}, closing writer.")
                return False
            except Exception as e:
                await asyncio.sleep(0.005)
                continue

    async def handleConnection(self, reader, writer):
        (clientAddress, clientPort) = writer.get_extra_info('peername')
        self.diameterLogger.debug(f"[Diameter] Initial Connection from: {clientAddress} on port {clientPort}")

        if False in await asyncio.gather(self.readRequestData(reader=reader, clientAddress=clientAddress, clientPort=clientPort, socketTimeout=self.socketTimeout), 
                                         self.writeResponseData(writer=writer, clientAddress=clientAddress, clientPort=clientPort)):
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