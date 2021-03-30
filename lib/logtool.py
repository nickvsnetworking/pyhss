import logging
import logging.handlers as handlers
import os
import sys
sys.path.append(os.path.realpath('../'))
import yaml
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

if yaml_config['redis']['enabled'] == True:
    logging.debug("Redis support enabled")
    import redis
    redis_store = redis.Redis(host=str(yaml_config['redis']['host']), port=str(yaml_config['redis']['port']), db=0)
    try:
        redis_store.incr('restart_count')
        if yaml_config['redis']['clear_stats_on_boot'] == True:
            logging.debug("Clearing all Redis keys")
            redis_store.flushall()
        else:
            logging.debug("Leaving prexisting Redis keys")
        logging.info("Connected to Redis server")
    except:
        logging.error("Failed to connect to Redis server - Disabling")
        yaml_config['redis']['enabled'] == False
        
#function for handling incrimenting Redis counters with error handling
def RedisIncrimenter(name):
    if yaml_config['redis']['enabled'] == True:
        try:
            redis_store.incr(name)
        except:
            logging.error("failed to incriment " + str(name))


def setup_logger(logger_name, log_file, level=logging.DEBUG):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s \t %(levelname)s \t %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a+')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    rolloverHandler = handlers.RotatingFileHandler(log_file, maxBytes=500000000, backupCount=5)
    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)
    l.addHandler(rolloverHandler)