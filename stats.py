import redis
r = redis.Redis(host='localhost', port=6379, db=0)
keys = r.keys()
for key in sorted(keys):
    value = r.get(key)
    print("Key: " + str(key) + " value: " + str(value))

