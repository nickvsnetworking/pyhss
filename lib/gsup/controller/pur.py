# PyHSS GSUP PurgeUE Controller
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
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
