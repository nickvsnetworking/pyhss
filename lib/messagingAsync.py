import asyncio
import redis.asyncio as redis
import time, json

class RedisMessagingAsync:
    """
    PyHSS Redis Asynchronous Message Service
    A class for sending and receiving redis messages asynchronously.
    """

    def __init__(self, host: str='localhost', port: int=6379):
        self.redisClient = redis.Redis(host=host, port=port)

    async def sendMessage(self, queue: str, message: str, queueExpiry: int=None) -> str:
        """
        Stores a message in a given Queue (Key) asynchronously and sets an expiry (in seconds) if provided.
        """
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                sendMessageResult = await(redisPipe.rpush(queue, message).execute())
                if queueExpiry is not None:
                    expireKeyResult = await(redisPipe.expire(queue, queueExpiry).execute())
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

        metricQueueName = f"metric-{serviceName}-{metricTimestamp}"
        
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                sendMetricResult = await(redisPipe.rpush(metricQueueName, prometheusMetricBody).execute())
            if metricExpiry is not None:
                expireKeyResult = await(redisPipe.expire(metricQueueName, metricExpiry).execute())
            return f'Succesfully stored metric called: {metricName}, with value of: {metricType}'
        except Exception as e:
            return ''

    async def getMessage(self, queue: str) -> str:
        """
        Gets the oldest message from a given Queue (Key) asynchronously, while removing it from the key as well. Deletes the key if the last message is being removed.
        """
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                message = await(redisPipe.lpop(queue).execute())
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
            print(e)
            return ''

    async def getQueues(self, pattern: str='*') -> list:
        """
        Returns all Queues (Keys) in the database, asynchronously.
        """
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                allQueues = await(redisPipe.keys(pattern).execute())
                return [x.decode() for x in allQueues[0]]
        except Exception as e:
            return []
    
    async def getNextQueue(self, pattern: str='*') -> str:
        """
        Returns the next Queue (Key) in the list, asynchronously.
        """
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                nextQueue = await(redisPipe.keys(pattern).execute())
                return nextQueue[0][0].decode()
        except Exception as e:
            return ''

    async def deleteQueue(self, queue: str) -> bool:
        """
        Deletes the given Queue (Key) asynchronously.
        """
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                await(redisPipe.delete(queue).execute())
            return True
        except Exception as e:
            return False
        
    async def closeConnection(self) -> bool:
        await self.redisClient.close()
        return True


if __name__ == '__main__':
    redisMessaging = RedisMessagingAsync()
    print(redisMessaging.getNextQueue())