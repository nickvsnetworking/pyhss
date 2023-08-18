import asyncio
import sctp, socket
import sys, os, binascii
import time
sys.path.append(os.path.realpath('../lib'))
from messaging import RedisMessaging
from diameter import Diameter


class DiameterService():
    """
    PyHSS Diameter Service
    A class for handling diameter requests and replies on Port 3868, via TCP or SCTP.
    """

    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):
        self.redisMessaging = RedisMessaging(host=redisHost, port=redisPort)
        self.diameterLibrary = Diameter()
        pass

    def validateDiameterRequest(self, requestData) -> bool:
        try:
            packetVars, avps = self.diameterLibrary.decode_diameter_packet(requestData)
            originHost = self.diameterLibrary.get_avp_data(avps, 264)[0]
            originHost = binascii.unhexlify(originHost).decode("utf-8")
        except Exception as e:
            return False
        return True
    
    async def readRequestData(self, reader, clientAddress: str, clientPort: str) -> bool:
        requestQueueName = f"{clientAddress}-{clientPort}-requests"
        print("In readRequestData")

        while True:
            requestData = await reader.read(1024)
            if len(requestData) > 0:
                print(f"Received data from {clientAddress} on port {clientPort}")
                print(f"Data: {binascii.hexlify(requestData)}")

                if not self.validateDiameterRequest(requestData):
                    print(f"Invalid Diameter Request.")
                    break

                requestHexString = binascii.hexlify(requestData)
                print(requestHexString)
                self.redisMessaging.sendMessage(queue=requestQueueName, message=requestHexString)

    async def writeResponseData(self, writer, clientAddress: str, clientPort: str) -> bool:
        responseQueueName = f"{clientAddress}-{clientPort}-responses"
        print("In writeResponseData")

        while True:
            responseHexString = self.redisMessaging.getMessage(queue=responseQueueName)
            if not len(responseHexString) > 0:
                await asyncio.sleep(0.005)
                continue

            diameterResponse = f'Received diameter request successfully.'
            print(f"Sending: {diameterResponse}")
            writer.write(diameterResponse)
            await writer.drain()

    async def handleConnection(self, reader, writer):
        (clientAddress, clientPort) = writer.get_extra_info('peername')
        if not await asyncio.gather(self.readRequestData(reader=reader, clientAddress=clientAddress, clientPort=clientPort),
                                    self.writeResponseData(writer=writer, clientAddress=clientAddress, clientPort=clientPort)):
            print("Closing Connection")
            writer.close()
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
        print(f'Serving on {servingAddresses}')
            
        async with server:
            await server.serve_forever()


if __name__ == '__main__':
    diameterService = DiameterService()
    asyncio.run(diameterService.startServer())