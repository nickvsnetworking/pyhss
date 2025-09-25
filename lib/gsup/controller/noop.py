"""
    PyHSS GSUP Noop Controller - A controller that does nothing for a given message (e.g. like an answer)
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
from osmocom.gsup.message import GsupMessage

from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.protocol.ipa_peer import IPAPeer
from logtool import LogTool


class NoopController(GsupController):
    def __init__(self, logger: LogTool, database: Database):
        super().__init__(logger, database)

    async def handle_message(self, peer: IPAPeer, message: GsupMessage):
        await self._logger.logAsync(service='GSUP', level='DEBUG', message=f"Nothing to do for {message.msg_type.name} from {peer}. Ignoring.")