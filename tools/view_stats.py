# This utility prints PyHSS stats stored in Redis
import sys
import json
import redis
from pyhss_config import config


r = redis.Redis(host=str(config['redis']['host']), port=str(config['redis']['port']), db=0)
keys = r.keys()
for key in sorted(keys):
    if key != b'ActivePeerDict':
        value = r.get(key)
        print("Key: " + str(key) + " value: " + str(value))


print("\n\nDiameter Peers:")
ActivePeerDict = r.get('ActivePeerDict')
if ActivePeerDict is None or len(ActivePeerDict) == 0:
    print("No connected peers.")
    sys.exit()
ActivePeerDict = json.loads(ActivePeerDict)

for keys in ActivePeerDict:
    print(keys)
    for subkeys in ActivePeerDict[keys]:
        print("\t" + str(subkeys) + ": \t" + str(ActivePeerDict[keys][subkeys]))
    print('\n')
