import os, sys, json, yaml
import time, logging
sys.path.append(os.path.realpath('../lib'))
from messaging import RedisMessaging
from diameter import Diameter
from banners import Banners
from logtool import LogTool

class HssService:
    
    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):

        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[HSS] Fatal Error - config.yaml not found, exiting.")
            quit()
        self.redisMessaging = RedisMessaging(host=redisHost, port=redisPort)
        self.logTool = LogTool()
        self.banners = Banners()
        self.hssLogger = self.logTool.setupLogger(loggerName='HSS', config=self.config)
        self.mnc = self.config.get('hss', {}).get('MNC', '999')
        self.mcc = self.config.get('hss', {}).get('MCC', '999')
        self.originRealm = self.config.get('hss', {}).get('OriginRealm', f'mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org')
        self.originHost = self.config.get('hss', {}).get('OriginHost', f'hss01')
        self.productName = self.config.get('hss', {}).get('ProductName', f'PyHSS')
        self.diameterLibrary = Diameter(originHost=self.originHost, originRealm=self.originRealm, productName=self.productName, mcc=self.mcc, mnc=self.mnc)
        self.hssLogger.info(self.banners.hssService())



    def handleOutboundResponse(self, queue: str, diameterResponse: str):
        self.redisMessaging.sendMessage(queue=queue, message=diameterResponse, queueExpiry=60)

    def handleRequestQueue(self):
        try:
            requestQueue = self.redisMessaging.getNextQueue(pattern='diameter-request*')
            requestMessage = self.redisMessaging.getMessage(queue=requestQueue)
            assert(len(requestMessage))
            self.hssLogger.debug(f"[HSS] Inbound Diameter Request Queue: {requestQueue}")
            self.hssLogger.debug(f"[HSS] Inbound Diameter Request: {requestMessage}")

            requestDict = json.loads(requestMessage)
            requestBinary = bytes.fromhex(next(iter(requestDict.values())))
            requestHost = str(requestQueue).split('-')[2]
            requestPort = str(requestQueue).split('-')[3]
            requestTimestamp = str(requestQueue).split('-')[4]

            diameterResponse = self.diameterLibrary.generateDiameterResponse(requestBinaryData=requestBinary)
            self.hssLogger.debug(f"[HSS] Generated Diameter Response: {diameterResponse}")
            if not len(diameterResponse) > 0:
                return False
            
            outboundResponseQueue = f"diameter-response-{requestHost}-{requestPort}-{requestTimestamp}"
            outboundResponse = json.dumps({"diameter-response": diameterResponse})

            self.hssLogger.debug(f"[HSS] Outbound Diameter Response Queue: {outboundResponseQueue}")
            self.hssLogger.debug(f"[HSS] Outbound Diameter Response: {outboundResponse}")

            self.handleOutboundResponse(queue=outboundResponseQueue, diameterResponse=outboundResponse)
            time.sleep(0.005)

        except Exception as e:
            return False


if __name__ == '__main__':
    hssService = HssService()
    while True:
        hssService.handleRequestQueue()