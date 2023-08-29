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
        self.logTool = LogTool(self.config)
        self.banners = Banners()
        self.redisMessaging = RedisMessaging(host=redisHost, port=redisPort)
        self.remotePeers = self.config.get('geored', {}).get('sync_endpoints', [])
        if not self.config.get('geored', {}).get('enabled'):
            self.logger.error("[Geored] Fatal Error - geored not enabled under geored.enabled, exiting.")
            quit()
        if not (len(self.remotePeers) > 0):
            self.logger.error("[Geored] Fatal Error - no peers defined under geored.sync_endpoints, exiting.")
            quit()
        self.logTool.log(service='Geored', level='info', message=f"{self.banners.georedService()}", redisClient=self.redisMessaging)

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
                            self.logTool.log(service='Geored', level='debug', message=f"[Geored] [sendGeored] Operation {operation} executed successfully on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}", redisClient=self.redisMessaging)

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
                    self.logTool.log(service='Geored', level='warning', message=f"[Geored] [sendGeored] Operation {operation} failed on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}", redisClient=self.redisMessaging)
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
                    self.logTool.log(service='Geored', level='warning', message=f"[Geored] [sendGeored] Operation {operation} timed out on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}", redisClient=self.redisMessaging)
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
                    self.logTool.log(service='Geored', level='error', message=f"[Geored] [sendGeored] Operation {operation} encountered unknown error on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}", redisClient=self.redisMessaging)
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

    def sendWebhook(self, url: str, operation: str, body: str, transactionId: str=uuid.uuid4(), retryCount: int=3) -> bool:
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
                            self.logTool.log(service='Geored', level='debug', message=f"[Geored] [sendWebhook] Operation {operation} executed successfully on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}", redisClient=self.redisMessaging)

                            self.redisMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                                                                metricType='counter', metricAction='inc', 
                                                                metricValue=1.0, metricHelp='Number of Webhook Pushes',
                                                                metricLabels={
                                                                "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                                                                "endpoint": "webhook",
                                                                "http_response_code": str(response.status_code),
                                                                "error": ""},
                                                                metricExpiry=60)
                            break
                        else:
                            self.redisMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                                    metricType='counter', metricAction='inc', 
                                    metricValue=1.0, metricHelp='Number of Webhook Pushes',
                                    metricLabels={
                                    "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                                    "endpoint": "webhook",
                                    "http_response_code": str(response.status_code),
                                    "error": str(response.reason)},
                                    metricExpiry=60)
                except requests.exceptions.ConnectionError as e:
                    error_message = str(e)
                    self.logTool.log(service='Geored', level='warning', message=f"[Geored] [sendWebhook] Operation {operation} failed on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}", redisClient=self.redisMessaging)
                    if "Name or service not known" in error_message:
                        self.redisMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                        metricType='counter', metricAction='inc', 
                        metricValue=1.0, metricHelp='Number of Webhook Pushes',
                        metricLabels={
                        "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                        "endpoint": "webhook",
                        "http_response_code": "000",
                        "error": "No matching DNS entry found"},
                        metricExpiry=60)
                    else:
                        self.redisMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webook',
                        metricType='counter', metricAction='inc', 
                        metricValue=1.0, metricHelp='Number of Webhook Pushes',
                        metricLabels={
                        "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                        "endpoint": "webhook",
                        "http_response_code": "000",
                        "error": "Connection Refused"},
                        metricExpiry=60)
                except requests.exceptions.Timeout:
                    self.logTool.log(service='Geored', level='warning', message=f"[Geored] [sendGeored] Operation {operation} timed out on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}", redisClient=self.redisMessaging)
                    self.redisMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                    metricType='counter', metricAction='inc', 
                    metricValue=1.0, metricHelp='Number of Webhook Pushes',
                    metricLabels={
                    "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                    "endpoint": "webhook",
                    "http_response_code": "000",
                    "error": "Timeout"},
                    metricExpiry=60)
                except Exception as e:
                    self.logTool.log(service='Geored', level='error', message=f"[Geored] [sendGeored] Operation {operation} encountered unknown error on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {response.status_code}. Error Message: {e}", redisClient=self.redisMessaging)
                    self.redisMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                    metricType='counter', metricAction='inc', 
                    metricValue=1.0, metricHelp='Number of Webhook Pushes',
                    metricLabels={
                    "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                    "endpoint": "webhook",
                    "http_response_code": "000",
                    "error": e},
                    metricExpiry=60)
            return True


    def handleQueue(self):
        try:
            georedQueue = self.redisMessaging.getNextQueue(pattern='geored-*')
            georedMessage = self.redisMessaging.getMessage(queue=georedQueue)
            assert(len(georedMessage))
            self.logTool.log(service='Geored', level='debug', message=f"[Geored] Queue: {georedQueue}", redisClient=self.redisMessaging)
            self.logTool.log(service='Geored', level='debug', message=f"[Geored] Message: {georedMessage}", redisClient=self.redisMessaging)

            georedDict = json.loads(georedMessage)
            georedOperation = georedDict['operation']
            georedBody = georedDict['body']

            try:
                for remotePeer in self.remotePeers:
                    self.sendGeored(url=remotePeer+'/geored/', operation=georedOperation, body=georedBody)
            except Exception as e:
                self.logTool.log(service='Geored', level='debug', message=f"[Geored] Error sending geored message: {e}", redisClient=self.redisMessaging)

        except Exception as e:
            return False

if __name__ == '__main__':
    georedService = GeoredService()
    while True:
        georedService.handleQueue()