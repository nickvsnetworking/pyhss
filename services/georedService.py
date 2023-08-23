import os, sys, json, yaml
import requests, uuid
sys.path.append(os.path.realpath('../lib'))
from messaging import RedisMessaging
from banners import Banners
from logtool import LogTool

class GeoredService:

    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):
        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[Geored] Fatal Error - config.yaml not found, exiting.")
            quit()
        self.logTool = LogTool()
        self.banners = Banners()
        self.georedLogger = self.logTool.setupLogger(loggerName='Geored', config=self.config)
        self.georedLogger.info(self.banners.georedService())
        self.redisMessaging = RedisMessaging(host=redisHost, port=redisPort)
        self.remotePeers = self.config.get('geored', {}).get('sync_endpoints', [])
        if not self.config.get('geored', {}).get('enabled'):
            self.logger.error("[Geored] Fatal Error - geored not enabled under geored.enabled, exiting.")
            quit()
        if not (len(self.remotePeers) > 0):
            self.logger.error("[Geored] Fatal Error - no peers defined under geored.sync_endpoints, exiting.")
            quit()

    def sendGeored(self, url: str, operation: str, body: str, transactionId: str=uuid.uuid4(), retryCount: int=3) -> bool:
            operation = operation.upper()
            requestOperations = {'GET': requests.get, 'PUT': requests.put, 'POST': requests.post, 'PATCH':requests.patch, 'DELETE': requests.delete}

            if not url or not operation or not body:
                return False

            if operation not in requestOperations:
                return False
            
            headers = {"Content-Type": "application/json", "Transaction-Id": str(transactionId)}
            
            for attempt in range(retryCount):
                try:
                    if operation in ['PUT', 'POST', 'PATCH']:
                        response = requestOperations[operation](url, json=body, headers=headers)
                    else:
                        response = requestOperations[operation](url, headers=headers)
                        if 200 <= response.status_code <= 299:
                            self.georedLogger.debug(f"[Geored] Operation {operation} executed successfully on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}")

                            self.redisMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                                                                metricType='counter', metricAction='inc', 
                                                                metricValue=1.0, metricHelp='Number of Geored Pushes',
                                                                metricLabels={
                                                                "geored_host": str(url.replace('https://', '').replace('http://', '')),
                                                                "endpoint": "geored",
                                                                "http_response_code": str(response.status_code),
                                                                "error": ""},
                                                                metricExpiry=60)
                            break
                        else:
                            self.redisMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                                    metricType='counter', metricAction='inc', 
                                    metricValue=1.0, metricHelp='Number of Geored Pushes',
                                    metricLabels={
                                    "geored_host": str(url.replace('https://', '').replace('http://', '')),
                                    "endpoint": "geored",
                                    "http_response_code": str(response.status_code),
                                    "error": str(response.reason)},
                                    metricExpiry=60)
                except requests.exceptions.ConnectionError as e:
                    error_message = str(e)
                    self.georedLogger.warning(f"[Geored] Operation {operation} failed on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}")
                    if "Name or service not known" in error_message:
                        self.redisMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                        metricType='counter', metricAction='inc', 
                        metricValue=1.0, metricHelp='Number of Geored Pushes',
                        metricLabels={
                        "geored_host": str(url.replace('https://', '').replace('http://', '')),
                        "endpoint": "geored",
                        "http_response_code": "000",
                        "error": "No matching DNS entry found"},
                        metricExpiry=60)
                    else:
                        self.redisMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                        metricType='counter', metricAction='inc', 
                        metricValue=1.0, metricHelp='Number of Geored Pushes',
                        metricLabels={
                        "geored_host": str(url.replace('https://', '').replace('http://', '')),
                        "endpoint": "geored",
                        "http_response_code": "000",
                        "error": "Connection Refused"},
                        metricExpiry=60)
                except requests.exceptions.Timeout:
                    self.georedLogger.warning(f"[Geored] Operation {operation} timed out on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}")
                    self.redisMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                    metricType='counter', metricAction='inc', 
                    metricValue=1.0, metricHelp='Number of Geored Pushes',
                    metricLabels={
                    "geored_host": str(url.replace('https://', '').replace('http://', '')),
                    "endpoint": "geored",
                    "http_response_code": "000",
                    "error": "Timeout"},
                    metricExpiry=60)
                except Exception as e:
                    self.georedLogger.error(f"[Geored] Operation {operation} encountered unknown error on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}")
                    self.redisMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                    metricType='counter', metricAction='inc', 
                    metricValue=1.0, metricHelp='Number of Geored Pushes',
                    metricLabels={
                    "geored_host": str(url.replace('https://', '').replace('http://', '')),
                    "endpoint": "geored",
                    "http_response_code": "000",
                    "error": e},
                    metricExpiry=60)
            return True

    def handleGeoredQueue(self):
        try:
            georedQueue = self.redisMessaging.getNextQueue(pattern='geored-*')
            georedMessage = self.redisMessaging.getMessage(queue=georedQueue)
            assert(len(georedMessage))
            self.georedLogger.debug(f"[Geored] Queue: {georedQueue}")
            self.georedLogger.debug(f"[Geored] Message: {georedMessage}")

            georedDict = json.loads(georedMessage)
            georedOperation = georedDict['operation']
            georedBody = georedDict['body']

            for remotePeer in self.remotePeers:
                self.sendGeored(url=remotePeer+'/geored/', operation=georedOperation, body=georedBody)

        except Exception as e:
            return False

if __name__ == '__main__':
    georedService = GeoredService()
    while True:
        georedService.handleGeoredQueue()