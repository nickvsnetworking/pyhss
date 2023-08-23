import asyncio
import sys, os, json
import time, json, yaml
from prometheus_client import make_wsgi_app, start_http_server, Counter, Gauge, Summary, Histogram, CollectorRegistry
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from flask import Flask
import threading
sys.path.append(os.path.realpath('../lib'))
from messaging import RedisMessaging
from banners import Banners
from logtool import LogTool

class MetricService:

    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):
        try:
            with open("../config.yaml", "r") as self.configFile:
                self.config = yaml.safe_load(self.configFile)
        except:
            print(f"[HSS] Fatal Error - config.yaml not found, exiting.")
            quit()
    
        self.redisMessaging = RedisMessaging(host=redisHost, port=redisPort)
        self.banners = Banners()
        self.logTool = LogTool()
        self.registry = CollectorRegistry(auto_describe=True)
        self.metricLogger = self.logTool.setupLogger(loggerName='Metric', config=self.config)
        self.metricLogger.info(self.banners.metricService())

    
    def handleMetrics(self):
        try:
            actions = {'inc': 'inc', 'dec': 'dec', 'set':'set'}
            prometheusTypes = {'counter': Counter, 'gauge': Gauge, 'histogram': Histogram, 'summary': Summary}

            metricQueue = self.redisMessaging.getNextQueue(pattern='metric-*')
            metric = self.redisMessaging.getMessage(queue=metricQueue)
            if not (len(metric) > 0):
                return
            self.metricLogger.info(f"Received Metric: {metric}")
            prometheusJsonList = json.loads(metric)
            for prometheusJson in prometheusJsonList:
                self.metricLogger.debug(prometheusJson)
                if not all(key in prometheusJson for key in ('NAME', 'TYPE', 'ACTION', 'VALUE')):
                    raise ValueError('All fields are not available for parsing')
                counterName = prometheusJson['NAME']
                counterType = prometheusTypes.get(prometheusJson['TYPE'].lower())
                counterAction = prometheusJson['ACTION'].lower()
                counterValue = float(prometheusJson['VALUE'])
                counterHelp = prometheusJson.get('HELP', '')
                counterLabels = prometheusJson.get('LABELS', {})

                if isinstance(counterLabels, list):
                            counterLabels = dict()

                if counterType is not None:
                    try:
                        counterRecord = counterType(counterName, counterHelp, labelnames=counterLabels.keys(), registry=self.registry)
                        if counterLabels:
                            counterRecord = counterRecord.labels(*counterLabels.values())
                    except ValueError as e:
                        counterRecord = self.registry._names_to_collectors.get(counterName)
                        if counterLabels and counterRecord:
                            counterRecord = counterRecord.labels(*counterLabels.values())
                    action = actions.get(counterAction)
                    if action is not None:
                        # Here we dynamically lookup the class from prometheus_client, and grab the matched function name called 'action'.
                        prometheusMethod = getattr(counterRecord, action)
                        prometheusMethod(counterValue)
                    else:
                        self.metricLogger.debug(f"Invalid action `{counterAction}` in message: {metric}, skipping.")
                        continue
                else:
                    self.metricLogger.debug(f"Invalid type `{counterType}` in message: {metric}, skipping.")
                    continue

        except Exception as e:
            self.metricLogger.error(f"Unable to parse message: {metric}, due to {e}. Skipping.")
            return


    def getMetrics(self):
        while True:
            self.handleMetrics()


if __name__ == '__main__':

    metricService = MetricService()
    metricServiceThread = threading.Thread(target=metricService.getMetrics)
    metricServiceThread.start()

    prometheusWebClient = Flask(__name__)
    prometheusWebClient.wsgi_app = DispatcherMiddleware(prometheusWebClient.wsgi_app, {
        '/metrics': make_wsgi_app(registry=metricService.registry)
    })

    #Uncomment the statement below to run a local testing instance.

    prometheusWebClient.run(host='0.0.0.0', port=9191)