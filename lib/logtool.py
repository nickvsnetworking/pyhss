import logging
import os
import sys
sys.path.append(os.path.realpath('../'))
import yaml
from datetime import datetime
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

if yaml_config['redis']['enabled'] == True:
    logging.debug("Redis support enabled")
    import redis
    import json
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

def RedisStore(key, value):
    if yaml_config['redis']['enabled'] == True:
        try:
            redis_store.set(key, value)
        except:
            logging.error("failed to set Redis key " + str(key) + " to value " + str(value))    

def RedisHMStore(key, value):
    if yaml_config['redis']['enabled'] == True:
        try:
            redis_store.hmset(key, value)
        except:
            logging.error("failed to set Redis key " + str(key) + " to value " + str(value))    

def RedisHMGet(key):
    if yaml_config['redis']['enabled'] == True:
        try:
            return redis_store.hgetall(key)
        except:
            logging.error("failed to hmget Redis key " + str(key))    


def RedisGet(key):
    if yaml_config['redis']['enabled'] == True:
        try:
            redis_store.get(key)
        except:
            logging.error("failed to set Redis key " + str(key))    



def Add_Diameter_Peer(peername, ip, action):
    logging.debug("Adding Diameter peer to Redis with hostname" + str(peername) + " and IP " + str(ip))
    now = datetime.now()
    timestamp = str(now.strftime("%H:%M:%S"))
    if redis_store.exists('ActivePeerDict') == False:
        #Initialise empty active peer dict in Redis
        logging.debug("Populated new empty ActivePeerDict Redis key")
        ActivePeerDict = {}
        ActivePeerDict['internal'] = {"timestamp" : timestamp}
        RedisHMStore('ActivePeerDict', json.dumps(ActivePeerDict))
    else:
        if action == "add":
            ActivePeerDict = str(RedisHMGet('ActivePeerDict'))
            print("data back from Redis")
            print(ActivePeerDict)
            ActivePeerDict = json.loads(ActivePeerDict)
            ActivePeerDict[peername] = {"timestamp" : timestamp, "ip" : str(ip)}
            RedisHMStore('ActivePeerDict', json.dumps(ActivePeerDict))


def setup_logger(logger_name, log_file, level=logging.DEBUG):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s \t %(levelname)s \t %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a+')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)