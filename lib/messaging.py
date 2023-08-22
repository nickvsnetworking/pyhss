from redis import Redis

class RedisMessaging:
    """
    PyHSS Redis Message Service
    A class for sending and receiving redis messages.
    """

    def __init__(self, host: str='localhost', port: int=6379):
        self.redisClient = Redis(host=host, port=port)
        pass

    def sendMessage(self, queue: str, message: str, queueExpiry: int=None) -> str:
        """
        Stores a message in a given Queue (Key).
        """
        try:
            self.redisClient.rpush(queue, message)
            if queueExpiry is not None:
                self.redisClient.expire(queue, queueExpiry)
            return f'{message} stored in {queue} successfully.'
        except Exception as e:
            return ''

    def getMessage(self, queue: str) -> str:
        """
        Gets the oldest message from a given Queue (Key), while removing it from the key as well. Deletes the key if the last message is being removed.
        """
        try:
            message = self.redisClient.lpop(queue)
            if message is None:
                message = ''
            else:
                try:
                    message = message.decode()
                except (UnicodeDecodeError, AttributeError):
                    pass
            return message
        except Exception as e:
            return ''

    def getQueues(self, pattern: str='*') -> list:
        """
        Returns all Queues (Keys) in the database.
        """
        try:
            allQueues = self.redisClient.keys(pattern)
            return [x.decode() for x in allQueues]
        except Exception as e:
            return []
    
    def getNextQueue(self, pattern: str='*') -> dict:
        """
        Returns the next Queue (Key) in the list.
        """
        try:
            for nextQueue in self.redisClient.scan_iter(match=pattern):
                return nextQueue.decode()
        except Exception as e:
            return {}

    def deleteQueue(self, queue: str) -> bool:
        """
        Deletes the given Queue (Key)
        """
        try:
            self.redisClient.delete(queue)
            return True
        except Exception as e:
            return False


if __name__ == '__main__':
    redisMessaging = RedisMessaging()
    print(redisMessaging.getNextQueue())