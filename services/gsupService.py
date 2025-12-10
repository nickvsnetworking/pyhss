# PyHSS GSUP Service
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import os
import sys

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))

from gsup.server import GsupServer
from logtool import LogTool
from pyhss_config import config
from messaging import RedisMessaging


def main():
    bind_ip = config['hss']['gsup']['bind_ip']
    bind_port = config['hss']['gsup']['bind_port']

    redis_host = config.get("redis", {}).get("host", "127.0.0.1")
    redis_port = int(config.get("redis", {}).get("port", 6379))
    redis_use_unix_socket = config.get('redis', {}).get('useUnixSocket', False)
    redis_unix_socket_path = config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')

    redis_messaging = RedisMessaging(host=redis_host, port=redis_port, useUnixSocket=redis_use_unix_socket,
                                     unixSocketPath=redis_unix_socket_path)

    gsup_server = GsupServer(bind_ip, bind_port, 60, LogTool(config), redis_messaging)
    asyncio.run(gsup_server.start_server())


if __name__ == '__main__':
    main()
