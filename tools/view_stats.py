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


print("\n\nDiameter Peers:")
ActivePeerDict = r.get('ActivePeerDict')
if len(ActivePeerDict) == 0:
    print("No connected peers.")
ActivePeerDict = json.loads(ActivePeerDict)

for keys in ActivePeerDict:
    print(keys)
    for subkeys in ActivePeerDict[keys]:
        print("\t" + str(subkeys) + ": \t" + str(ActivePeerDict[keys][subkeys]))
    print('\n')