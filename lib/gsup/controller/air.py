"""
    PyHSS GSUP Authentication Info Request Controller
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

import traceback

from osmocom.gsup.message import GsupMessage, MsgType

from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.protocol.gsup_msg import GsupMessageUtil, GsupMessageBuilder
from gsup.protocol.ipa_peer import IPAPeer
from logtool import LogTool


class AIRController(GsupController):
    def __init__(self, logger: LogTool, database: Database):
        super().__init__(logger, database)

    async def handle_message(self, peer: IPAPeer, message: GsupMessage):
        request_dict = message.to_dict()
        imsi = GsupMessageUtil.get_first_ie_by_name(GsupMessageUtil.GSUP_MSG_IE_IMSI, request_dict)
        if imsi is None:
            await self._logger.logAsync(service='GSUP', level='WARN',
                                        message=f"Missing IMSI in GSUP message from {peer}. Responding with error.")
            await self._send_gsup_response(peer, GsupMessageBuilder().with_msg_type(
                MsgType.SEND_AUTH_INFO_ERROR).build())
            return

        try:
            subscriber = self._database.Get_Subscriber(imsi=imsi)
            rand = GsupMessageUtil.get_first_ie_by_name('rand', request_dict)
            auts = GsupMessageUtil.get_first_ie_by_name('auts', request_dict)

            resync_required = rand is not None and auts is not None
            if resync_required:
                self._database.Get_Vectors_AuC(subscriber['auc_id'], 'sqn_resync', rand=rand, auts=auts.hex())
            vectors = self._database.Get_Vectors_AuC(subscriber['auc_id'], '2g3g', requested_vectors=1)

            response_msg = ((GsupMessageBuilder()
                             .with_msg_type(MsgType.SEND_AUTH_INFO_RESULT))
                            .with_ie('imsi', imsi)
                            .with_ie('auth_tuple', vectors))

            response_msg = response_msg.build()

            await self._send_gsup_response(peer, response_msg)

        except ValueError as e:
            await self._logger.logAsync(service='GSUP', level='WARN', message=f"Subscriber not found: {imsi}")
            await self._send_gsup_response(peer, GsupMessageBuilder().with_msg_type(
                MsgType.SEND_AUTH_INFO_ERROR).with_ie('imsi', imsi).build())
        except Exception as e:
            await self._logger.logAsync(service='GSUP', level='ERROR', message=f"Error handling GSUP message: {str(e)}, {traceback.format_exc()}")
            await self._send_gsup_response(peer, GsupMessageBuilder().with_msg_type(
                MsgType.SEND_AUTH_INFO_ERROR).with_ie('imsi', imsi).build())
