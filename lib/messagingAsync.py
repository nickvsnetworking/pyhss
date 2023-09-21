import asyncio
import redis.asyncio as redis
import time, json, uuid

class RedisMessagingAsync:
    """
    PyHSS Redis Asynchronous Message Service
    A class for sending and receiving redis messages asynchronously.
    """

    def __init__(self, host: str='localhost', port: int=6379):
        self.redisClient = redis.Redis(unix_socket_path='/var/run/redis/redis-server.sock')

    async def sendMessage(self, queue: str, message: str, queueExpiry: int=None) -> str:
        """
        Stores a message in a given Queue (Key) asynchronously and sets an expiry (in seconds) if provided.
        """
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                await redisPipe.rpush(queue, message)
                if queueExpiry is not None:
                    await redisPipe.expire(queue, queueExpiry)
                sendMessageResult, expireKeyResult = await redisPipe.execute()
            return f'{message} stored in {queue} successfully.'
        except Exception as e:
            return ''

    async def sendMetric(self, serviceName: str, metricName: str, metricType: str, metricAction: str, metricValue: float, metricHelp: str='', metricLabels: list=[], metricTimestamp: int=time.time_ns(), metricExpiry: int=None) -> str:
        """
        Stores a prometheus metric in a format readable by the metric service, asynchronously.
        """
        if not isinstance(metricValue, (int, float)):
            return 'Invalid Argument: metricValue must be a digit'
        metricValue = float(metricValue)
        prometheusMetricBody = json.dumps([{
        'NAME': metricName,
        'TYPE': metricType,
        'HELP': metricHelp,
        'LABELS': metricLabels,
        'ACTION': metricAction,
        'VALUE': metricValue,
        }
        ])

        metricQueueName = f"metric-{serviceName}-{metricTimestamp}-{uuid.uuid4()}"
        
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                await(redisPipe.rpush(metricQueueName, prometheusMetricBody).execute())
                if metricExpiry is not None:
                    await(redisPipe.expire(metricQueueName, metricExpiry).execute())
                    sendMetricResult, expireKeyResult = await redisPipe.execute()
            return f'Succesfully stored metric called: {metricName}, with value of: {metricType}'
        except Exception as e:
            return ''

    async def sendLogMessage(self, serviceName: str, logLevel: str, logTimestamp: int, message: str, logExpiry: int=None) -> str:
        """
        Stores a log message in a given Queue (Key) asynchronously and sets an expiry (in seconds) if provided.
        """
        try:
            logQueueName = f"log-{serviceName}-{logLevel}-{logTimestamp}-{uuid.uuid4()}"
            logMessage = json.dumps({"message": message})
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                await redisPipe.rpush(logQueueName, logMessage)
                if logExpiry is not None:
                    await redisPipe.expire(logQueueName, logExpiry)
                sendMessageResult, expireKeyResult = await redisPipe.execute()
            return f'{message} stored in {logQueueName} successfully.'
        except Exception as e:
            return ''

    async def getMessage(self, queue: str) -> str:
        """
        Gets the oldest message from a given Queue (Key) asynchronously, while removing it from the key as well. Deletes the key if the last message is being removed.
        """
        try:
                message = await(self.redisClient.lpop(queue))
                if message is None:
                    message = ''
                else:
                    try:
                        if message[0] is None:
                            return ''
                        else:
                            message = message[0].decode()
                    except (UnicodeDecodeError, AttributeError):
                        pass
                return message
        except Exception as e:
            return ''

    async def getQueues(self, pattern: str='*') -> list:
        """
        Returns all Queues (Keys) in the database, asynchronously.
        """
        try:
                allQueuesBinary = await(self.redisClient.keys(pattern))
                allQueues = [x.decode() for x in allQueuesBinary]
                return allQueues
        except Exception as e:
            return []
    
    async def getNextQueue(self, pattern: str='*') -> str:
        """
        Returns the next Queue (Key) in the list, asynchronously.
        """
        try:
            async for nextQueue in self.redisClient.scan_iter(match=pattern):
                if nextQueue is not None:
                    return nextQueue.decode('utf-8')
        except Exception as e:
            print(e)
        return ''

    async def deleteQueue(self, queue: str) -> bool:
        """
        Deletes the given Queue (Key) asynchronously.
        """
        try:
            deleteQueueResult = await(self.redisClient.delete(queue))
            return True
        except Exception as e:
            return False

    async def setValue(self, key: str, value: str, keyExpiry: int=None) -> str:
        """
        Stores a value under a given key asynchronously and sets an expiry (in seconds) if provided.
        """
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                await redisPipe.set(key, value)
                if keyExpiry is not None:
                    await redisPipe.expire(key, value)
                setValueResult, expireValueResult = await redisPipe.execute()
            return f'{value} stored in {key} successfully.'
        except Exception as e:
            return ''

    async def getValue(self, key: str) -> str:
        """
        Gets the value stored under a given key asynchronously.
        """
        try:
                message = await(self.redisClient.get(key))
                if message is None:
                    message = ''
                else:
                    return message
        except Exception as e:
            return ''

    async def closeConnection(self) -> bool:
        await self.redisClient.close()
        return True


if __name__ == '__main__':
    redisMessaging = RedisMessagingAsync()
    print(redisMessaging.getNextQueue())