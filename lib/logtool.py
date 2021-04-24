import logging
import logging.handlers as handlers
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
    import pickle
    redis_store = redis.Redis(host=str(yaml_config['redis']['host']), port=str(yaml_config['redis']['port']), db=0)
    try:
        redis_store.incr('restart_count')
        if yaml_config['redis']['clear_stats_on_boot'] == True:
            logging.debug("Clearing all Redis keys")
            redis_store.flushall()
        else:
            logging.debug("Leaving prexisting Redis keys")
        #Clear ActivePeerDict
        redis_store.delete('ActivePeerDict')
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

def RedisGet(key):
    if yaml_config['redis']['enabled'] == True:
        try:
            return redis_store.get(key)
        except:
            logging.error("failed to set Redis key " + str(key))    



def RedisStoreDict(key, value):
    if yaml_config['redis']['enabled'] == True:
        try:
            redis_store.set(str(key), pickle.dumps(value))
        except:
            logging.error("failed to set Redis dict " + str(key) + " to value " + str(value))    

def RedisGetDict(key):
    if yaml_config['redis']['enabled'] == True:
        try:
            read_dict = redis_store.get(key)
            return pickle.loads(read_dict)
        except:
            logging.error("failed to hmget Redis key " + str(key))    




def Manage_Diameter_Peer(peername, ip, action):
    try:
        logging.debug("Adding Diameter peer to Redis with hostname" + str(peername) + " and IP " + str(ip))
        now = datetime.now()
        timestamp = str(now.strftime("%Y-%m-%d %H:%M:%S"))

        #Try and get IP and Port seperately
        try:
            ip = ip[0]
            port = ip[1]
        except:
            pass

        if redis_store.exists('ActivePeerDict') == False:
            #Initialise empty active peer dict in Redis
            logging.debug("Populated new empty ActivePeerDict Redis key")
            ActivePeerDict = {}
            ActivePeerDict['internal_connection'] = {"connect_timestamp" : timestamp}
            RedisStore('ActivePeerDict', json.dumps(ActivePeerDict))
        
        if action == "add":
            data = RedisGet('ActivePeerDict')
            ActivePeerDict = json.loads(data)
            logging.debug("ActivePeerDict back from Redis" + str(ActivePeerDict) + " to add peer " + str(peername) + " with ip " + str(ip))


            #If key has already existed in dict due to disconnect / reconnect, get reconnection count
            try:
                reconnection_count = ActivePeerDict[str(ip)]['reconnection_count'] + 1
            except:
                reconnection_count = 0

            ActivePeerDict[str(ip)] = {"connect_timestamp" : timestamp, \
                "recv_ip_address" : str(ip), "DiameterHostname" : "Unknown - Socket connection only", \
                "reconnection_count" : reconnection_count,
                "connection_status" : "Pending"}
            RedisStore('ActivePeerDict', json.dumps(ActivePeerDict))

        if action == "remove":
            data = RedisGet('ActivePeerDict')
            ActivePeerDict = json.loads(data)
            logging.debug("ActivePeerDict back from Redis" + str(ActivePeerDict))
            ActivePeerDict[str(ip)] = {"disconnect_timestamp" : str(timestamp), \
                "DiameterHostname" : str(ActivePeerDict[str(ip)]['DiameterHostname']), \
                "reconnection_count" : ActivePeerDict[str(ip)]['reconnection_count'],
                "connection_status" : "Disconnected"}
            RedisStore('ActivePeerDict', json.dumps(ActivePeerDict))        

        if action == "update":
            data = RedisGet('ActivePeerDict')
            ActivePeerDict = json.loads(data)
            ActivePeerDict[str(ip)]['DiameterHostname'] = str(peername)
            ActivePeerDict[str(ip)]['last_dwr_timestamp'] = str(timestamp)
            ActivePeerDict[str(ip)]['connection_status'] = "Connected"
            RedisStore('ActivePeerDict', json.dumps(ActivePeerDict))
    except:
        logging.error("failed to add/update/remove Diameter peer from Redis")
        

def setup_logger(logger_name, log_file, level=logging.DEBUG):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s \t %(levelname)s \t %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a+')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    rolloverHandler = handlers.RotatingFileHandler(log_file, maxBytes=50000000, backupCount=5)
    l.setLevel(level)
    l.addHandler(fileHandler)
    l.addHandler(streamHandler)
    l.addHandler(rolloverHandler)
