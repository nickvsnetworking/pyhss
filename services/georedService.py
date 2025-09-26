import os, sys, json, yaml
import uuid, time
import asyncio, aiohttp
import socket
import traceback
sys.path.append(os.path.realpath('../lib'))
from messagingAsync import RedisMessagingAsync
from banners import Banners
from logtool import LogTool
from database import geored_check_updated_endpoints

class GeoredService:
    """
    PyHSS Geored Service
    Handles updating and sending webhooks to remote endpoints.
    """

    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):
        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[Geored] Fatal Error - config.yaml not found, exiting.")
            quit()
        self.logTool = LogTool(self.config)
        self.banners = Banners()

        self.redisUseUnixSocket = self.config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = self.config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = self.config.get('redis', {}).get('host', 'localhost')
        self.redisPort = self.config.get('redis', {}).get('port', 6379)
        self.redisGeoredMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.redisWebhookMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        
        self.georedPeers = geored_check_updated_endpoints(self.config)
        self.webhookPeers = self.config.get('webhooks', {}).get('endpoints', [])
        self.ocsPeers = self.config.get('ocs', {}).get('endpoints', [])
        self.ocsNotificationsEnabled = self.config.get('ocs', {}).get('enabled', False)
        self.benchmarking = self.config.get('hss').get('enable_benchmarking', False)
        self.hostname = socket.gethostname()

        if not self.config.get('geored', {}).get('enabled'):
            self.logger.error("[Geored] Fatal Error - geored not enabled under geored.enabled, exiting.")
            quit()
        if self.georedPeers is not None:
            if not (len(self.georedPeers) > 0):
                self.logger.error("[Geored] Fatal Error - no peers defined under geored.sync_endpoints, exiting.")
                quit()

    async def sendGeored(self, asyncSession, url: str, operation: str, body: str, transactionId: str=uuid.uuid4(), retryCount: int=3) -> bool:
            """
            Sends a Geored HTTP request to a given endpoint.
            """
            if self.benchmarking:
                startTime = time.perf_counter()
            operation = operation.upper()
            requestOperations = {'GET': asyncSession.get, 'PUT': asyncSession.put, 'POST': asyncSession.post, 'PATCH':asyncSession.patch, 'DELETE': asyncSession.delete}

            if not url or not operation or not body:
                return False

            if operation not in requestOperations:
                return False
            
            headers = {"Content-Type": "application/json", "Transaction-Id": str(transactionId), "User-Agent": f"PyHSS/1.0.1 (Geored)"}

            for attempt in range(retryCount):
                try:
                    responseStatusCode = None
                    responseBody = None

                    if operation in ['PUT', 'POST', 'PATCH']:
                        async with requestOperations[operation](url, json=body, headers=headers) as response:
                            responseBody = await(response.text())
                            responseStatusCode = response.status
                    else:
                        async with requestOperations[operation](url, headers=headers) as response:
                            responseBody = await(response.text())
                            responseStatusCode = response.status

                    if 200 <= responseStatusCode <= 299:
                        await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [sendGeored] Operation {operation} executed successfully on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {responseStatusCode}"))

                        asyncio.ensure_future(self.redisGeoredMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                                                            metricType='counter', metricAction='inc', 
                                                            metricValue=1.0, metricHelp='Number of Geored Pushes',
                                                            metricLabels={
                                                            "geored_host": str(url.replace('https://', '').replace('http://', '')),
                                                            "endpoint": "geored",
                                                            "http_response_code": str(responseStatusCode),
                                                            "error": ""},
                                                            metricExpiry=60,
                                                            usePrefix=True, 
                                                            prefixHostname=self.hostname, 
                                                            prefixServiceName='metric'))
                        break
                    else:
                        asyncio.ensure_future(self.redisGeoredMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                                metricType='counter', metricAction='inc', 
                                metricValue=1.0, metricHelp='Number of Geored Pushes',
                                metricLabels={
                                "geored_host": str(url.replace('https://', '').replace('http://', '')),
                                "endpoint": "geored",
                                "http_response_code": str(responseStatusCode),
                                "error": str(response.reason)},
                                metricExpiry=60,
                                usePrefix=True, 
                                prefixHostname=self.hostname, 
                                prefixServiceName='metric'))
                except aiohttp.ClientConnectionError as e:
                    error_message = str(e)
                    await(self.logTool.logAsync(service='Geored', level='warning', message=f"[Geored] [sendGeored] Operation {operation} failed on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {responseStatusCode}. Error Message: {e}"))
                    if "Name or service not known" in error_message:
                        asyncio.ensure_future(self.redisGeoredMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                        metricType='counter', metricAction='inc', 
                        metricValue=1.0, metricHelp='Number of Geored Pushes',
                        metricLabels={
                        "geored_host": str(url.replace('https://', '').replace('http://', '')),
                        "endpoint": "geored",
                        "http_response_code": "000",
                        "error": "No matching DNS entry found"},
                        metricExpiry=60,
                        usePrefix=True, 
                        prefixHostname=self.hostname, 
                        prefixServiceName='metric'))
                    else:
                        asyncio.ensure_future(self.redisGeoredMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                        metricType='counter', metricAction='inc', 
                        metricValue=1.0, metricHelp='Number of Geored Pushes',
                        metricLabels={
                        "geored_host": str(url.replace('https://', '').replace('http://', '')),
                        "endpoint": "geored",
                        "http_response_code": "000",
                        "error": "Connection Refused"},
                        metricExpiry=60,
                        usePrefix=True, 
                        prefixHostname=self.hostname, 
                        prefixServiceName='metric'))
                except aiohttp.ServerTimeoutError:
                    await(self.logTool.logAsync(service='Geored', level='warning', message=f"[Geored] [sendGeored] Operation {operation} timed out on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {responseStatusCode}. Error Message: {e}"))
                    asyncio.ensure_future(self.redisGeoredMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                    metricType='counter', metricAction='inc', 
                    metricValue=1.0, metricHelp='Number of Geored Pushes',
                    metricLabels={
                    "geored_host": str(url.replace('https://', '').replace('http://', '')),
                    "endpoint": "geored",
                    "http_response_code": "000",
                    "error": "Timeout"},
                    metricExpiry=60,
                    usePrefix=True, 
                    prefixHostname=self.hostname, 
                    prefixServiceName='metric'))
                except Exception as e:
                    await(self.logTool.logAsync(service='Geored', level='error', message=f"[Geored] [sendGeored] Operation {operation} encountered unknown error on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {responseStatusCode}. Error Message: {e}"))
                    asyncio.ensure_future(self.redisGeoredMessaging.sendMetric(serviceName='geored', metricName='prom_http_geored',
                    metricType='counter', metricAction='inc', 
                    metricValue=1.0, metricHelp='Number of Geored Pushes',
                    metricLabels={
                    "geored_host": str(url.replace('https://', '').replace('http://', '')),
                    "endpoint": "geored",
                    "http_response_code": "000",
                    "error": e},
                    metricExpiry=60,
                    usePrefix=True, 
                    prefixHostname=self.hostname, 
                    prefixServiceName='metric'))
            if self.benchmarking:
                await(self.logTool.logAsync(service='Geored', level='info', message=f"[Geored] [sendGeored] Time taken to send individual geored request to {url}: {round(((time.perf_counter() - startTime)*1000), 3)} ms"))

            return True

    async def sendWebhook(self, asyncSession, url: str, operation: str, body: str, headers: dict, transactionId: str=uuid.uuid4(), retryCount: int=3) -> bool:
            """
            Sends a Webhook HTTP request to a given endpoint.
            """
            if self.benchmarking:
                startTime = time.perf_counter()
            operation = operation.upper()
            requestOperations = {'GET': asyncSession.get, 'PUT': asyncSession.put, 'POST': asyncSession.post, 'PATCH':asyncSession.patch, 'DELETE': asyncSession.delete}

            if not url or not operation or not body or not headers:
                return False

            if operation not in requestOperations:
                return False
            
            if 'User-Agent' not in headers:
                headers['User-Agent'] = f"PyHSS/1.0.1 (Webhook)"

            for attempt in range(retryCount):
                try:
                    responseStatusCode = None
                    responseBody = None

                    if operation in ['PUT', 'POST', 'PATCH']:
                        async with requestOperations[operation](url, json=body, headers=headers) as response:
                            responseBody = await(response.text())
                            responseStatusCode = response.status
                    else:
                        async with requestOperations[operation](url, headers=headers) as response:
                            responseBody = await(response.text())
                            responseStatusCode = response.status

                    if 200 <= responseStatusCode <= 299:
                        await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [sendWebhook] Operation {operation} executed successfully on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {responseStatusCode}"))

                        asyncio.ensure_future(self.redisWebhookMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                                                            metricType='counter', metricAction='inc', 
                                                            metricValue=1.0, metricHelp='Number of Webhook Pushes',
                                                            metricLabels={
                                                            "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                                                            "endpoint": "webhook",
                                                            "http_response_code": str(responseStatusCode),
                                                            "error": ""},
                                                            metricExpiry=60,
                                                            usePrefix=True, 
                                                            prefixHostname=self.hostname, 
                                                            prefixServiceName='metric'))
                        break
                    else:
                        asyncio.ensure_future(self.redisWebhookMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                                metricType='counter', metricAction='inc', 
                                metricValue=1.0, metricHelp='Number of Webhook Pushes',
                                metricLabels={
                                "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                                "endpoint": "webhook",
                                "http_response_code": str(responseStatusCode),
                                "error": str(response.reason)},
                                metricExpiry=60,
                                usePrefix=True, 
                                prefixHostname=self.hostname, 
                                prefixServiceName='metric'))
                except aiohttp.ClientConnectionError as e:
                    error_message = str(e)
                    await(self.logTool.logAsync(service='Geored', level='warning', message=f"[Geored] [sendWebhook] Operation {operation} failed on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {responseStatusCode}. Error Message: {e}"))
                    if "Name or service not known" in error_message:
                        asyncio.ensure_future(self.redisWebhookMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                        metricType='counter', metricAction='inc', 
                        metricValue=1.0, metricHelp='Number of Webhook Pushes',
                        metricLabels={
                        "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                        "endpoint": "webhook",
                        "http_response_code": "000",
                        "error": "No matching DNS entry found"},
                        metricExpiry=60,
                        usePrefix=True, 
                        prefixHostname=self.hostname, 
                        prefixServiceName='metric'))
                    else:
                        asyncio.ensure_future(self.redisWebhookMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                        metricType='counter', metricAction='inc', 
                        metricValue=1.0, metricHelp='Number of Webhook Pushes',
                        metricLabels={
                        "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                        "endpoint": "webhook",
                        "http_response_code": "000",
                        "error": "Connection Refused"},
                        metricExpiry=60,
                        usePrefix=True, 
                        prefixHostname=self.hostname, 
                        prefixServiceName='metric'))
                except aiohttp.ServerTimeoutError:
                    await(self.logTool.logAsync(service='Geored', level='warning', message=f"[Geored] [sendWebhook] Operation {operation} timed out on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {responseStatusCode}. Error Message: {e}"))
                    asyncio.ensure_future(self.redisWebhookMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                    metricType='counter', metricAction='inc', 
                    metricValue=1.0, metricHelp='Number of Webhook Pushes',
                    metricLabels={
                    "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                    "endpoint": "webhook",
                    "http_response_code": "000",
                    "error": "Timeout"},
                    metricExpiry=60,
                    usePrefix=True, 
                    prefixHostname=self.hostname, 
                    prefixServiceName='metric'))
                except Exception as e:
                    await(self.logTool.logAsync(service='Geored', level='error', message=f"[Geored] [sendWebhook] Operation {operation} encountered unknown error on {url}, with body: ({body}) and transactionId {transactionId}. Response code: {responseStatusCode}. Error Message: {traceback.format_exc()}"))
                    asyncio.ensure_future(self.redisWebhookMessaging.sendMetric(serviceName='webhook', metricName='prom_http_webhook',
                    metricType='counter', metricAction='inc', 
                    metricValue=1.0, metricHelp='Number of Webhook Pushes',
                    metricLabels={
                    "webhook_host": str(url.replace('https://', '').replace('http://', '')),
                    "endpoint": "webhook",
                    "http_response_code": "000",
                    "error": e},
                    metricExpiry=60,
                    usePrefix=True, 
                    prefixHostname=self.hostname, 
                    prefixServiceName='metric'))
            if self.benchmarking:
                await(self.logTool.logAsync(service='Geored', level='info', message=f"[Geored] [sendWebhook] Time taken to send individual webhook request to {url}: {round(((time.perf_counter() - startTime)*1000), 3)} ms"))

            return True

    async def handleAsymmetricGeoredQueue(self):
        """
        Collects and processes asymmetric geored messages.
        """
        while True:
            try:
                if self.benchmarking:
                    startTime = time.perf_counter()
                georedMessage = json.loads((await(self.redisGeoredMessaging.awaitMessage(key='asymmetric-geored', usePrefix=True, prefixHostname=self.hostname, prefixServiceName='geored')))[1])
                await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [handleAsymmetricGeoredQueue] Message: {georedMessage}"))

                georedOperation = georedMessage['operation']
                georedBody = georedMessage['body']
                georedUrls = georedMessage['urls']
                georedTasks = []

                socketSession = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
                async with socketSession as session:
                    for georedEndpoint in georedUrls:
                        georedTasks.append(self.sendGeored(asyncSession=session, url=georedEndpoint, operation=georedOperation, body=georedBody))
                    await asyncio.gather(*georedTasks)
                if self.benchmarking:
                    await(self.logTool.logAsync(service='Geored', level='info', message=f"[Geored] [handleAsymmetricGeoredQueue] Time taken to send asymmetric geored message to specified peers: {round(((time.perf_counter() - startTime)*1000), 3)} ms"))

                await(asyncio.sleep(0))

            except Exception as e:
                await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [handleAsymmetricGeoredQueue] Error handling asymmetric geored queue: {e}"))
                await(asyncio.sleep(0))
                continue

    async def handleGeoredQueue(self):
        """
        Collects and processes queued geored messages.
        """
        while True:
            try:
                if self.benchmarking:
                    startTime = time.perf_counter()
                georedMessage = json.loads((await(self.redisGeoredMessaging.awaitMessage(key='geored', usePrefix=True, prefixHostname=self.hostname, prefixServiceName='geored')))[1])
                await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [handleGeoredQueue] Message: {georedMessage}"))

                georedOperation = georedMessage['operation']
                georedBody = georedMessage['body']
                georedTasks = []

                socketSession = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
                async with socketSession as session:
                    self.georedPeers = geored_check_updated_endpoints(self.config)
                    for remotePeer in self.georedPeers:
                        georedTasks.append(self.sendGeored(asyncSession=session, url=remotePeer+'/geored/', operation=georedOperation, body=georedBody))
                    await asyncio.gather(*georedTasks)
                if self.benchmarking:
                    await(self.logTool.logAsync(service='Geored', level='info', message=f"[Geored] [handleGeoredQueue] Time taken to send geored message to all geored peers: {round(((time.perf_counter() - startTime)*1000), 3)} ms"))

                await(asyncio.sleep(0))

            except Exception as e:
                await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [handleGeoredQueue] Error handling geored queue: {e}"))
                await(asyncio.sleep(0))
                continue
    
    async def handleWebhookQueue(self):
        """
        Collects and processes queued webhook messages.
        """
        while True:
            try:
                if self.benchmarking:
                    startTime = time.perf_counter()
                webhookMessage = json.loads((await(self.redisWebhookMessaging.awaitMessage(key='webhook', usePrefix=True, prefixHostname=self.hostname, prefixServiceName='webhook')))[1])

                await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [handleWebhookQueue] Message: {webhookMessage}"))

                webhookType = 'other'

                notificationType = webhookMessage.get('notification_type', None)
                if notificationType:
                    if 'ocs' in notificationType.lower():
                        webhookType = 'ocs'

                webhookHeaders = webhookMessage['headers']
                webhookOperation = webhookMessage['operation']
                webhookBody = webhookMessage['body']
                webhookTasks = []
                
                socketSession = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
                async with socketSession as session:
                    if webhookType == 'ocs':
                        if self.ocsNotificationsEnabled:
                            for remotePeer in self.ocsPeers:
                                await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [handleWebhookQueue] Sending OCS Notification to: {remotePeer}"))
                                webhookTasks.append(self.sendWebhook(asyncSession=session, url=remotePeer, operation=webhookOperation, body=webhookBody, headers=webhookHeaders))
                            await asyncio.gather(*webhookTasks)
                    else:
                        for remotePeer in self.webhookPeers:
                            await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [handleWebhookQueue] Sending Notification to: {remotePeer}"))
                            webhookTasks.append(self.sendWebhook(asyncSession=session, url=remotePeer, operation=webhookOperation, body=webhookBody, headers=webhookHeaders))
                        await asyncio.gather(*webhookTasks)
                if self.benchmarking:
                    await(self.logTool.logAsync(service='Geored', level='info', message=f"[Geored] [handleWebhookQueue] Time taken to send webhook to all geored peers: {round(((time.perf_counter() - startTime)*1000), 3)} ms"))
                await(asyncio.sleep(0.001))

            except Exception as e:
                await(self.logTool.logAsync(service='Geored', level='debug', message=f"[Geored] [handleWebhookQueue] Error handling webhook queue: {e}"))
                await(asyncio.sleep(0.001))
                continue

    async def startService(self):
        """
        Performs sanity checks on configuration and starts the geored and webhook tasks, when enabled.
        """
        await(self.logTool.logAsync(service='Geored', level='info', message=f"{self.banners.georedService()}"))
        while True:

            georedEnabled = self.config.get('geored', {}).get('enabled', False)
            webhooksEnabled = self.config.get('webhooks', {}).get('enabled', False)

            self.georedPeers = geored_check_updated_endpoints(self.config)
            if self.georedPeers is not None:
                if not len(self.georedPeers) > 0:
                    georedEnabled = False

            if not georedEnabled and not webhooksEnabled:
                await(self.logTool.logAsync(service='Geored', level='info', message=f"[Geored] [startService] Geored and Webhook services both disabled or missing peers, exiting."))
                sys.exit()

            activeTasks = []

            if georedEnabled:
                georedTask = asyncio.create_task(self.handleGeoredQueue())
                asymmetricGeoredTask = asyncio.create_task(self.handleAsymmetricGeoredQueue())
                activeTasks.append(georedTask)
                activeTasks.append(asymmetricGeoredTask)
            
            if webhooksEnabled:
                webhookTask = asyncio.create_task(self.handleWebhookQueue())
                activeTasks.append(webhookTask)

            completeTasks, pendingTasks = await(asyncio.wait(activeTasks, return_when=asyncio.FIRST_COMPLETED))

            if len(pendingTasks) > 0:
                for pendingTask in pendingTasks:
                    try:
                        pendingTask.cancel()
                        await(asyncio.sleep(0.001))
                    except asyncio.CancelledError:
                        pass


if __name__ == '__main__':
    georedService = GeoredService()
    asyncio.run(georedService.startService())
