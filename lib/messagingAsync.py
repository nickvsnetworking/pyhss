import asyncio
import traceback
import socket
import redis.asyncio as redis
from redis.asyncio.sentinel import Sentinel
import time, json, uuid

class RedisMessagingAsync:
    """
    PyHSS Redis Asynchronous Message Service
    A class for sending and receiving redis messages asynchronously.
    """

    def __init__(self, host: str='localhost', port: int=6379, useUnixSocket: bool=False, unixSocketPath: str='/var/run/redis/redis-server.sock'):
        if useUnixSocket:
            self.redisClient = redis.Redis(unix_socket_path=unixSocketPath)
        else:
            self.redisClient = redis.Redis(host=host, port=port)
        pass

    async def handlePrefix(self, key: str, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common'):
        """
        Adds a prefix to the Key or Queue name, if enabled.
        Returns the same Key or Queue if not enabled.
        """
        if usePrefix:
            return f"{prefixHostname}:{prefixServiceName}:{key}"
        else:
            return key

    async def sendMessage(self, queue: str, message: str, queueExpiry: int=None, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> str:
        """
        Stores a message in a given Queue (Key) asynchronously and sets an expiry (in seconds) if provided.
        """
        try:
            queue = await(self.handlePrefix(key=queue, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            await(self.redisClient.rpush(queue, message))
            if queueExpiry is not None:
                 await(self.redisClient.expire(queue, queueExpiry))
            return f'{message} stored in {queue} successfully.'
        except Exception as e:
            return ''

    async def sendBulkMessage(self, queue: str, messageList: list, queueExpiry: int=None, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> str:
        """
        Empties a given asyncio queue into a redis pipeline, then sends to redis.
        """
        try:
            queue = await(self.handlePrefix(key=queue, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            redisPipe = self.redisClient.pipeline()

            for message in messageList:
                redisPipe.rpush(queue, message)
                if queueExpiry is not None:
                    redisPipe.expire(queue, queueExpiry)
                
            await(redisPipe.execute())
            
            return f'Messages stored in {queue} successfully.'
        
        except Exception as e:
            return ''

    async def sendMetric(self, serviceName: str, metricName: str, metricType: str, metricAction: str, metricValue: float, metricHelp: str='', metricLabels: list=[], metricTimestamp: int=time.time_ns(), metricExpiry: int=None, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> str:
        """
        Stores a prometheus metric in a format readable by the metric service, asynchronously.
        """
        if not isinstance(metricValue, (int, float)):
            return 'Invalid Argument: metricValue must be a digit'
        metricValue = float(metricValue)
        prometheusMetricBody = json.dumps([{
        'serviceName': serviceName,
        'timestamp': metricTimestamp,
        'NAME': metricName,
        'TYPE': metricType,
        'HELP': metricHelp,
        'LABELS': metricLabels,
        'ACTION': metricAction,
        'VALUE': metricValue,
        }
        ])

        metricQueueName = f"metric"
        metricQueueName = await(self.handlePrefix(key=metricQueueName, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
        
        try:
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                await(redisPipe.rpush(metricQueueName, prometheusMetricBody).execute())
                if metricExpiry is not None:
                    await(redisPipe.expire(metricQueueName, metricExpiry).execute())
                    sendMetricResult, expireKeyResult = await redisPipe.execute()
            return f'Succesfully stored metric called: {metricName}, with value of: {metricType}'
        except Exception as e:
            return ''

    async def sendLogMessage(self, serviceName: str, logLevel: str, logTimestamp: int, message: str, logExpiry: int=None, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> str:
        """
        Stores a log message in a given Queue (Key) asynchronously and sets an expiry (in seconds) if provided.
        """
        try:
            logQueueName = f"log"
            logQueueName = await(self.handlePrefix(key=logQueueName, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            logMessage = json.dumps({"message": message, "service": serviceName, "level": logLevel, "timestamp": logTimestamp})
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                await redisPipe.rpush(logQueueName, logMessage)
                if logExpiry is not None:
                    await redisPipe.expire(logQueueName, logExpiry)
                sendMessageResult, expireKeyResult = await redisPipe.execute()
            return f'{message} stored in {logQueueName} successfully.'
        except Exception as e:
            return ''

    async def getMessage(self, queue: str, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> str:
        """
        Gets the oldest message from a given Queue (Key) asynchronously, while removing it from the key as well. Deletes the key if the last message is being removed.
        """
        try:
            queue = await(self.handlePrefix(key=queue, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
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

    async def getQueues(self, pattern: str='*', usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> list:
        """
        Returns all Queues (Keys) in the database, asynchronously.
        """
        try:
            pattern = await(self.handlePrefix(key=pattern, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            allQueuesBinary = []
            async for nextQueue in self.redisClient.scan_iter(match=pattern):
                if nextQueue:
                    allQueuesBinary.append(nextQueue)
            allQueues = [x.decode() for x in allQueuesBinary]
            return allQueues
        except Exception as e:
            print(traceback.format_exc())
            return []
    
    async def getNextQueue(self, pattern: str='*', usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> str:
        """
        Returns the next Queue (Key) in the list, asynchronously.
        """
        try:
            pattern = await(self.handlePrefix(key=pattern, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            async for nextQueue in self.redisClient.scan_iter(match=pattern):
                if nextQueue is not None:
                    return nextQueue.decode('utf-8')
        except Exception as e:
            print(e)
        return ''

    async def awaitMessage(self, key: str, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common'):
        """
        Asynchronously blocks until a message is received at the given key, then returns the message.
        """
        try:
            key = await(self.handlePrefix(key=key, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            message =  (await(self.redisClient.blpop(key)))
            return tuple(data.decode() for data in message)
        except Exception as e:
            return ''

    async def awaitBulkMessage(self, key: str, count: int=100, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common'):
        """
        Asynchronously blocks until one or more messages are received at the given key, then returns the amount of messages specified by count.
        """
        try:
            key = await(self.handlePrefix(key=key, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            message = await(self.redisClient.blmpop(0, 1, key, direction='RIGHT', count=count))
            return message
        except Exception as e:
            print(traceback.format_exc())
            return ''

    async def deleteQueue(self, queue: str, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> bool:
        """
        Deletes the given Queue (Key) asynchronously.
        """
        try:
            queue = await(self.handlePrefix(key=queue, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            deleteQueueResult = await(self.redisClient.delete(queue))
            return True
        except Exception as e:
            return False

    async def setValue(self, key: str, value: str, keyExpiry: int=None, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> str:
        """
        Stores a value under a given key asynchronously and sets an expiry (in seconds) if provided.
        """
        try:
            key = await(self.handlePrefix(key=key, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
            async with self.redisClient.pipeline(transaction=True) as redisPipe:
                await redisPipe.set(key, value)
                if keyExpiry is not None:
                    await redisPipe.expire(key, keyExpiry)
                setValueResult = await redisPipe.execute()
            return f'{value} stored in {key} successfully.'
        except Exception as e:
            return traceback.format_exc()

    async def getValue(self, key: str, usePrefix: bool=False, prefixHostname: str='unknown', prefixServiceName: str='common') -> str:
        """
        Gets the value stored under a given key asynchronously.
        """
        try:
            key = await(self.handlePrefix(key=key, usePrefix=usePrefix, prefixHostname=prefixHostname, prefixServiceName=prefixServiceName))
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