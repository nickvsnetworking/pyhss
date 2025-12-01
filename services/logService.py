# Copyright 2023-2024 David Kneipp <david@davidkneipp.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os, sys, json, socket
from datetime import datetime
import time
import logging

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))

from messaging import RedisMessaging
from banners import Banners
from logtool import LogTool
from pyhss_config import config


class LogService:
    """
    PyHSS Log Service
    A class for handling queued log entries in the Redis DB.
    This class is synchronous and not high-performance.
    """

    def __init__(self):
        self.logTool = LogTool(config=config)
        self.banners = Banners()
        self.redisUseUnixSocket = config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = config.get('redis', {}).get('host', 'localhost')
        self.redisPort = config.get('redis', {}).get('port', 6379)
        self.redisMessaging = RedisMessaging(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.logFilePaths = config.get('logging', {}).get('logfiles', {})
        self.logLevels = {
        'CRITICAL': {'verbosity': 1, 'logging': logging.CRITICAL},
        'ERROR': {'verbosity': 2, 'logging': logging.ERROR},
        'WARNING': {'verbosity': 3, 'logging':  logging.WARNING},
        'INFO': {'verbosity': 4, 'logging':  logging.INFO},
        'DEBUG': {'verbosity': 5, 'logging':  logging.DEBUG},
        'NOTSET': {'verbosity': 6, 'logging':  logging.NOTSET},
        }
        self.hostname = socket.gethostname()

        print(f"{self.banners.logService()}")

    def handleLogs(self):
        """
        Continually polls the Redis DB for queued log files. Parses and writes log files to disk, using LogTool.
        """
        activeLoggers = {}
        while True:
            try:
                logMessage = json.loads(self.redisMessaging.awaitMessage(key='log', usePrefix=True, prefixHostname=self.hostname, prefixServiceName='log')[1])

                print(f"[Log] Message: {logMessage}")

                logFileMessage = logMessage['message']
                logService = logMessage.get('service').lower()
                logLevel = logMessage.get('level').lower()
                logTimestamp = logMessage.get('timestamp')

                if f"{logService}_logging_file" not in self.logFilePaths:
                    continue

                logFileName = f"{logService}_logging_file"
                logFilePath = self.logFilePaths.get(logFileName, '/var/log/pyhss.log')

                if logService not in activeLoggers:
                    activeLoggers[logService] = self.logTool.setupFileLogger(loggerName=logService, logFilePath=logFilePath)

                fileLogger = activeLoggers[logService]
                fileLogger.log(self.logLevels.get(logLevel.upper(), {}).get('logging', logging.INFO), logFileMessage, extra={'timestamp': float(logTimestamp)})


            except Exception as e:
                self.logTool.log(service='Log', level='error', message=f"[Log] Error: {e}", redisClient=self.redisMessaging)
                continue


def main():
    logService = LogService()
    logService.handleLogs()


if __name__ == '__main__':
    main()
