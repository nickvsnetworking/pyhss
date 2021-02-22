#This utility prints PyHSS stats stored in Redis
import yaml
import sys
with open(sys.path[0] + '/../config.yaml') as stream:
    yaml_config = (yaml.safe_load(stream))

import redis
r = redis.Redis(host=str(yaml_config['redis']['host']), port=str(yaml_config['redis']['port']), db=0)
keys = r.keys()
for key in sorted(keys):
    value = r.get(key)
    print("Key: " + str(key) + " value: " + str(value))

r.incr('Answer_280_attempt_count')