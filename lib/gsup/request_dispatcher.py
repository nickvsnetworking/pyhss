"""
    PyHSS GSUP Request dispatcher
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

from typing import Dict

from osmocom.gsup.message import GsupMessage, MsgType

from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.controller.air import AIRController
from gsup.controller.isr import ISRController
from gsup.controller.noop import NoopController
from gsup.controller.pur import PURController
from gsup.controller.ulr import ULRTransaction, ULRController
from gsup.protocol.gsup_msg import GsupMessageBuilder, GsupMessageUtil
from gsup.protocol.ipa_peer import IPAPeer
from gsup.protocol.osmocom_ipa import IPA
from logtool import LogTool


class GsupRequestDispatcher:
    def __init__(self, logger: LogTool, database: Database, all_peers: Dict[str, IPAPeer]):
        self.__ulr_transactions: Dict[str, ULRTransaction] = dict()
        self.logger = logger
        self.database = database
        self.ipa = IPA()
        self.controller_mapping: Dict[MsgType, GsupController] = {
                MsgType.SEND_AUTH_INFO_REQUEST: AIRController(logger, database),
                MsgType.UPDATE_LOCATION_REQUEST: ULRController(logger, database, self.__ulr_transactions, all_peers),
                MsgType.INSERT_DATA_RESULT: ISRController(logger, database, self.__ulr_transactions),
                MsgType.INSERT_DATA_ERROR: ISRController(logger, database, self.__ulr_transactions),
                MsgType.LOCATION_CANCEL_RESULT: NoopController(logger, database),
                MsgType.LOCATION_CANCEL_ERROR: NoopController(logger, database),
                MsgType.AUTH_FAIL_REPORT: NoopController(logger, database),
                MsgType.PURGE_MS_REQUEST: PURController(logger, database),
        }


    async def dispatch(self, peer: IPAPeer, request: GsupMessage):
        # clean up old transactions
        transactions_to_remove = []
        for peer_name in list(self.__ulr_transactions.keys()):
            if self.__ulr_transactions[peer_name].is_finished():
                transactions_to_remove.append(peer_name)

        for peer_name in transactions_to_remove:
            del self.__ulr_transactions[peer_name]

        if request.msg_type in self.controller_mapping:
            await self.controller_mapping[request.msg_type].handle_message(peer, request)
            return

        await self.__handle_gsup_unhandled_request(peer, request)

    async def __send_gsup_response(self, peer: IPAPeer, response: GsupMessage):
        data = response.to_bytes()
        IPA.add_header(data, self.ipa.PROTO['OSMO'], self.ipa.EXT['GSUP'])
        peer.writer.write(data)
        await peer.writer.drain()

    async def __handle_gsup_unhandled_request(self, peer: IPAPeer, gsup: GsupMessage):
        error_responses = {
            MsgType.CHECK_IMEI_REQUEST: MsgType.CHECK_IMEI_ERROR,
            MsgType.DELETE_DATA_REQUEST: MsgType.DELETE_DATA_ERROR,
            MsgType.EPDG_TUNNEL_REQUEST: MsgType.EPDG_TUNNEL_ERROR,
            MsgType.LOCATION_CANCEL_REQUEST: MsgType.LOCATION_CANCEL_ERROR,
            MsgType.MO_FORWARD_SM_REQUEST: MsgType.MO_FORWARD_SM_ERROR,
            MsgType.MT_FORWARD_SM_REQUEST: MsgType.MT_FORWARD_SM_ERROR,
            MsgType.PROC_SS_REQUEST: MsgType.PROC_SS_ERROR,
            MsgType.READY_FOR_SM_REQUEST: MsgType.READY_FOR_SM_ERROR,
        }

        if gsup.msg_type in error_responses:
            builder = GsupMessageBuilder().with_msg_type(error_responses[gsup.msg_type])
            imsi = GsupMessageUtil.get_first_ie_by_name('imsi', gsup.to_dict())
            if imsi:
                builder.with_ie('imsi', imsi)
            await self.logger.logAsync(service='GSUP', level='WARN',
                                       message=f"Unhandled GSUP message {gsup.msg_type} from {peer}. Responding with error.")
            await self.__send_gsup_response(peer, builder)
            return

        raise ValueError(
            f"Unhandled GSUP message {gsup.msg_type} from {peer} to which I don't know how to respond. Closing connection.")
