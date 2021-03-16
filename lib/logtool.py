import logging
import os
import sys
sys.path.append(os.path.realpath('../'))
import yaml
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

if yaml_config['redis']['enabled'] == True:
    logging.debug("Redis support enabled")
    import redis

#function for handling incrimenting Redis counters with error handling
def RedisIncrimenter(self, name):
    if yaml_config['redis']['enabled'] == True:
        try:
            self.redis_store.incr(name)
        except:
            DiameterLogger.error("failed to incriment " + str(name))


def setup_logger(logger_name, log_file, level=logging.DEBUG):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s : %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a+')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)