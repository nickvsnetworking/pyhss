import logging
import logging.handlers as handlers
import os
import sys
sys.path.append(os.path.realpath('../'))

class LogTool:

    def setupLogger(self, loggerName: str, config: dict):
        logFile = config.get('logging', {}).get('logfiles', {}).get(f'{loggerName.lower()}_logging_file', '/var/log/pyhss_diameter.log')
        logLevel = config.get('logging', {}).get('level', 'INFO')
        logger = logging.getLogger(loggerName)
        formatter = logging.Formatter(fmt="%(asctime)s  %(levelname)s  {%(pathname)s:%(lineno)d}  %(message)s", datefmt="%m/%d/%Y %H:%M:%S %Z")
        try:
            rolloverHandler = handlers.RotatingFileHandler(logFile, maxBytes=50000000, backupCount=5)
        except PermissionError:
            logFileName = logFile.split('/')[-1]
            pyhssRootDir = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
            print(f"[LogTool] Warning - Unable to write to {logFile}, using {pyhssRootDir}/log/{logFileName} instead.")
            logFile = f"{pyhssRootDir}/log/{logFileName}"
            rolloverHandler = handlers.RotatingFileHandler(logFile, maxBytes=50000000, backupCount=5)
            pass
        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(formatter)
        rolloverHandler.setFormatter(formatter)
        logger.setLevel(logLevel)
        logger.addHandler(streamHandler)
        logger.addHandler(rolloverHandler)
        return logger 