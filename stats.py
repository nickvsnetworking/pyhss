import redis
r = redis.Redis(host='172.17.0.2', port=6379, db=0)
print(r.set('foo', 'bar'))
print(r.get('foo'))
