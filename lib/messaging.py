from redis import Redis

class RedisMessaging():
    """
    PyHSS Redis Message Service
    A class for sending and receiving redis messages.
    """

    def __init__(self, host: str='localhost', port: int=6379):
        self.redisClient = Redis(host=host, port=port)
        pass

    def sendMessage(self, queue: str, message: str) -> str:
        self.redisClient.rpush(queue, message)

    def getMessage(self, queue: str) -> str:
        message = self.redisClient.lpop(queue)
        if message is None:
            message = ''
        else:
            try:
                message = message.decode()
            except (UnicodeDecodeError, AttributeError):
                pass
        return message