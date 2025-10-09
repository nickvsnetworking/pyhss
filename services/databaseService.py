import os, sys, json
import uuid, time
import asyncio
import socket
import datetime
import traceback

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))

from messagingAsync import RedisMessagingAsync
from banners import Banners
from logtool import LogTool
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy import MetaData, Table
from pyhss_config import config

class DatabaseService:
    """
    Redis-Database Cache Service
    Functions as an asynchronous cache for a database.
    Currently read-only.
    """

    def __init__(self, redisHost: str='127.0.0.1', redisPort: int=6379):
        self.logTool = LogTool(config)
        self.banners = Banners()

        self.redisUseUnixSocket = config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = config.get('redis', {}).get('host', 'localhost')
        self.redisPort = config.get('redis', {}).get('port', 6379)
        self.redisDatabaseReadMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.redisLogMessaging = RedisMessagingAsync(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)
        self.hostname = socket.gethostname()

        supportedDatabaseTypes = ["mysql", "postgresql"]
        self.databaseType = config.get('database', {}).get('db_type', 'mysql').lower()
        if not self.databaseType in supportedDatabaseTypes:
            print(f"[Database] Fatal Error - unsupported database type: {self.databaseType}. Supported database types are: {supportedDatabaseTypes}, exiting.")
            quit()

        self.databaseHost = config.get('database', {}).get('server', '')
        self.databaseUsername = config.get('database', {}).get('username', '')
        self.databasePassword = config.get('database', {}).get('password', '')
        self.database = config.get('database', {}).get('database', '')
        self.readCacheEnabled = config.get('database', {}).get('readCacheEnabled', True)
        self.cacheReadInterval = int(config.get('database', {}).get('cacheReadInterval', 60))

        self.sqlAlchemyEngine = create_engine(
            f"{self.databaseType}://{self.databaseUsername}:{self.databasePassword}@{self.databaseHost}/{self.database}"
        )
        self.sqlAlchemySession = sessionmaker(bind=self.sqlAlchemyEngine)

    def sanitizeJson(self, obj):
        """
        Handles general JSON sanitizaion.
        """

        if isinstance(obj, datetime.datetime):
            return obj.isoformat()

        raise TypeError(f'Object of type {type(obj).__name__} is not JSON serializable')

    def safeClose(self, databaseSession):
        try:
            if databaseSession.is_active:
                databaseSession.close()
        except Exception as E:
            self.logTool.log(service='Database', level='error', message=f"[Database] [safeClose] Failed to safely close session: {traceback.format_exc()}", redisClient=self.redisLogMessaging)

    async def readDatabase(self):
        """
        Reads all database records and caches them into Redis.
        """
        while True:
            try:
                self.logTool.log(service='Database', level='debug', message=f"[Database] [readDatabase] Starting Read from database.", redisClient=self.redisLogMessaging)
                databaseMetadata = MetaData()
                databaseConnection = self.sqlAlchemyEngine.connect()
                databaseMetadata.reflect(bind=databaseConnection) 
                self.readSession = self.sqlAlchemySession()

                for tableName in databaseMetadata.tables:
                    tableObject = Table(tableName, databaseMetadata, autoloaded=True)
                    primaryKeyColumnNames = [primaryKeyColumn.name for primaryKeyColumn in tableObject.primary_key.columns.values()]
                    if not primaryKeyColumnNames:
                        continue
                    primaryKeyName = primaryKeyColumnNames[0]
                    records = self.readSession.query(tableObject).all()
                    for record in records:
                        recordDict = dict(record._mapping)
                        recordJson = json.dumps(recordDict, default=self.sanitizeJson)
                        self.logTool.log(service='Database', level='debug', message=f"[Database] [readDatabase] Updating Cache: {recordJson}", redisClient=self.redisLogMessaging)
                        recordId = primaryKeyName
                        await(self.redisDatabaseReadMessaging.sendMessage(queue=f'{tableName}', message=f"{recordId}:{recordJson}", queueExpiry=None, usePrefix=True, prefixHostname=self.hostname, prefixServiceName='database'))
                try:
                    self.safeClose(self.readSession)
                except:
                    pass
                self.logTool.log(service='Database', level='debug', message=f"[Database] [readDatabase] Finished Read from database.", redisClient=self.redisLogMessaging)
                await(asyncio.sleep(self.cacheReadInterval))

            except Exception as e:
                self.logTool.log(service='Database', level='error', message=f"[Database] [readDatabase] Error: {traceback.format_exc()}", redisClient=self.redisLogMessaging)
                try:
                    self.safeClose(self.readSession)
                except:
                    pass
                await(asyncio.sleep(self.cacheReadInterval))

    async def startService(self):
        """
        Performs sanity checks on configuration and starts the database service.
        """
        await(self.logTool.logAsync(service='Database', level='info', message=f"{self.banners.databaseService()}"))
        while True:

            if not self.readCacheEnabled:
                await(self.logTool.logAsync(service='Database', level='info', message=f"[Database] [startService] Database read cache enabled, exiting."))
                sys.exit()

            activeTasks = []

            readCacheTask = asyncio.create_task(self.readDatabase())
            activeTasks.append(readCacheTask)

            completeTasks, pendingTasks = await(asyncio.wait(activeTasks, return_when=asyncio.FIRST_COMPLETED))

            if len(pendingTasks) > 0:
                for pendingTask in pendingTasks:
                    try:
                        pendingTask.cancel()
                        await(asyncio.sleep(0.001))
                    except asyncio.CancelledError:
                        pass


if __name__ == '__main__':
    databaseService = DatabaseService()
    asyncio.run(databaseService.startService())
