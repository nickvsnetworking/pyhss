import logging
import logging.handlers as handlers
import os, sys, time
from datetime import datetime
sys.path.append(os.path.realpath('../'))
import asyncio

class TimestampFilter (logging.Filter):
    """
    Logging filter which checks for a `timestamp` attribute on a
    given LogRecord, and if present it will override the LogRecord creation time.
    Expects time.time() or equivalent integer.
    """

    def filter(self, record):
        if hasattr(record, 'timestamp'):
            record.created = record.timestamp
        return True

class LogTool:
    """
    Reusable logging class, providing both asynchronous and synchronous logging functions.
    """
    def __init__(self, config: dict):
        self.logLevels = {
        'CRITICAL': {'verbosity': 1, 'logging': logging.CRITICAL},
        'ERROR': {'verbosity': 2, 'logging': logging.ERROR},
        'WARNING': {'verbosity': 3, 'logging':  logging.WARNING},
        'INFO': {'verbosity': 4, 'logging':  logging.INFO},
        'DEBUG': {'verbosity': 5, 'logging':  logging.DEBUG},
        'NOTSET': {'verbosity': 6, 'logging':  logging.NOTSET},
        }
        self.logLevel = config.get('logging', {}).get('level', 'INFO')
    
    async def logAsync(self, service: str, level: str, message: str, redisClient) -> bool:
        """
        Tests loglevel, prints to console and queues a log message to an asynchronous redis messaging client.
        """
        configLogLevelVerbosity = self.logLevels.get(self.logLevel.upper(), {}).get('verbosity', 4)
        messageLogLevelVerbosity = self.logLevels.get(level.upper(), {}).get('verbosity', 4)
        if not messageLogLevelVerbosity <= configLogLevelVerbosity:
            return False
        timestamp = time.time()
        dateTimeString = datetime.fromtimestamp(timestamp).strftime("%m/%d/%Y %H:%M:%S %Z").strip()
        print(f"[{dateTimeString}] [{level.upper()}] {message}")
        asyncio.ensure_future(redisClient.sendLogMessage(serviceName=service.lower(), logLevel=level, logTimestamp=timestamp, message=message, logExpiry=60))
        return True
    
    def log(self, service: str, level: str, message: str, redisClient) -> bool:
        """
        Tests loglevel, prints to console and queues a log message to a synchronous redis messaging client.
        """
        configLogLevelVerbosity = self.logLevels.get(self.logLevel.upper(), {}).get('verbosity', 4)
        messageLogLevelVerbosity = self.logLevels.get(level.upper(), {}).get('verbosity', 4)
        if not messageLogLevelVerbosity <= configLogLevelVerbosity:
            return False
        timestamp = time.time()
        dateTimeString = datetime.fromtimestamp(timestamp).strftime("%m/%d/%Y %H:%M:%S %Z").strip()
        print(f"[{dateTimeString}] [{level.upper()}] {message}")
        redisClient.sendLogMessage(serviceName=service.lower(), logLevel=level, logTimestamp=timestamp, message=message, logExpiry=60)
        return True

    def setupFileLogger(self, loggerName: str, logFilePath: str):
        """
        Sets up and returns a file logger, given a loggerName and logFilePath. 
        Defaults to {pyhssRootDir}/log/{logFileName} if the configured file location is not writable.
        """
        try:
            rolloverHandler = handlers.RotatingFileHandler(logFilePath, maxBytes=50000000, backupCount=5)
        except PermissionError:
            logFileName = logFilePath.split('/')[-1]
            pyhssRootDir = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
            print(f"[LogTool] Warning - Unable to write to {logFilePath}, using {pyhssRootDir}/log/{logFileName} instead.")
            logFilePath = f"{pyhssRootDir}/log/{logFileName}"
            rolloverHandler = handlers.RotatingFileHandler(logFilePath, maxBytes=50000000, backupCount=5)
        fileLogger = logging.getLogger(loggerName)
        print(logFilePath)
        formatter = logging.Formatter(fmt="%(asctime)s  %(levelname)s  {%(pathname)s:%(lineno)d}  %(message)s", datefmt="%m/%d/%Y %H:%M:%S %Z")
        filter = TimestampFilter()
        fileLogger.addFilter(filter)
        rolloverHandler.setFormatter(formatter)
        fileLogger.addHandler(rolloverHandler)
        fileLogger.setLevel(logging.DEBUG)
        return fileLogger