"""
    PyHSS GSUP PurgeUE Controller
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

from osmocom.gsup.message import MsgType

from gsup.controller.abstract_controller import GsupController
from gsup.protocol.gsup_msg import GsupMessageUtil, GsupMessageBuilder


class PURController(GsupController):
    def __init__(self, logger, database):
        super().__init__(logger, database)

    async def handle_message(self, peer, message):
        imsi = GsupMessageUtil.get_first_ie_by_name('imsi', message.to_dict())
        if imsi is None:
            await self._logger.logAsync(service='GSUP', level='WARN', message=f"IMSI not found in PUR message from {peer}")
            response = GsupMessageBuilder().with_msg_type(MsgType.PURGE_MS_ERROR).build()
            await self._send_gsup_response(peer, response)
            return

        try:
            self._database.update_hlr(imsi, peer.role, None)
            await self._logger.logAsync(service='GSUP', level='INFO', message=f"Subscriber {imsi} purged from {peer}")
            response = GsupMessageBuilder().with_msg_type(MsgType.PURGE_MS_RESULT).with_ie('imsi', imsi).build()
            await self._send_gsup_response(peer, response)
        except Exception as e:
            await self._logger.logAsync(service='GSUP', level='ERROR', message=f"Error purging subscriber: {str(e)}")
            response = GsupMessageBuilder().with_msg_type(MsgType.PURGE_MS_ERROR).with_ie('imsi', imsi).build()
            await self._send_gsup_response(peer, response)