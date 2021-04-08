#This utility prints PyHSS stats stored in Redis
import yaml
import sys
with open(sys.path[0] + '/../config.yaml') as stream:
    yaml_config = (yaml.safe_load(stream))
import json
import redis
r = redis.Redis(host=str(yaml_config['redis']['host']), port=str(yaml_config['redis']['port']), db=0)
keys = r.keys()
for key in sorted(keys):
    if key != b'ActivePeerDict':
        value = r.get(key)
        print("Key: " + str(key) + " value: " + str(value))


ActivePeerDict = json.loads(r.get('ActivePeerDict'))
for keys in ActivePeerDict:
    print(keys)