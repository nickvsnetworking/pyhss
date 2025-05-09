"""
    PyHSS GSUP Service
    Copyright (C) 2025  Lennart Rosam <hello@takuto.de>
    Copyright (C) 2025  Alexander Couzens <lynxis@fe80.eu>

    SPDX-License-Identifier: AGPL-3.0-or-later

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import os
import sys

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))
import yaml

from gsup.server import GsupServer
from logtool import LogTool

if __name__ == '__main__':
    config = None
    try:
        with open("../config.yaml", "r") as configFile:
            config = yaml.safe_load(configFile)
    except:  # noqa
        print("Error reading configuration file")
        exit(1)

    bind_ip = config['hss']['gsup']['bind_ip']
    bind_port = config['hss']['gsup']['bind_port']

    gsup_server = GsupServer(bind_ip, bind_port, 60, LogTool(config))
    asyncio.run(gsup_server.start_server())