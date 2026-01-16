# PyHSS GSUP Authentication Info Request Controller
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
import traceback

from osmocom.gsup.message import GsupMessage, MsgType

from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.protocol.gsup_msg import GsupMessageUtil, GsupMessageBuilder, GMMCause
from gsup.protocol.ipa_peer import IPAPeer
from logtool import LogTool
from utils import validate_imsi, InvalidIMSI


class AIRController(GsupController):
    def __init__(self, logger: LogTool, database: Database):
        super().__init__(logger, database)

    def get_num_vectors_req(self, message: dict):
        # OSMO_GSUP_MAX_NUM_AUTH_INFO
        max_num = 5

        ret = GsupMessageUtil.get_first_ie_by_name('num_vectors_req', message)
        if not ret or ret > max_num:
            return max_num
        return ret

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
            validate_imsi(imsi)
            subscriber = self._database.Get_Subscriber(imsi=imsi)
            rand = GsupMessageUtil.get_first_ie_by_name('rand', request_dict)
            auts = GsupMessageUtil.get_first_ie_by_name('auts', request_dict)

            resync_required = rand is not None and auts is not None
            if resync_required:
                self._database.Get_Vectors_AuC(subscriber['auc_id'], 'sqn_resync', rand=rand, auts=auts.hex())

            # Use request_vectors=1 as Get_Vectors_AuC currently doesn't
            # increment SEQ for each requested vector:
            # https://github.com/nickvsnetworking/pyhss/issues/266
            vectors = []
            for i in range(self.get_num_vectors_req(request_dict)):
                vectors += self._database.Get_Vectors_AuC(subscriber['auc_id'], '2g3g', requested_vectors=1)

            response_msg = ((GsupMessageBuilder()
                            .with_msg_type(MsgType.SEND_AUTH_INFO_RESULT))
                            .with_ie('imsi', imsi))

            for vector in vectors:
                response_msg.with_ie('auth_tuple', [vector], False)

            response_msg = response_msg.build()

            await self._send_gsup_response(peer, response_msg)
        except InvalidIMSI as e:
            await self._logger.logAsync(service='GSUP', level='WARN', message=f"Invalid IMSI: {imsi}")
            await self._send_gsup_response(
                peer,
                GsupMessageBuilder().with_msg_type(MsgType.SEND_AUTH_INFO_ERROR)
                .with_ie('imsi', imsi)
                .with_ie('cause', GMMCause.INV_MAND_INFO.value)
                .build(),
            )
        except ValueError as e:
            await self._logger.logAsync(service='GSUP', level='WARN', message=f"Subscriber not found: {imsi}")
            await self._send_gsup_response(
                peer,
                GsupMessageBuilder().with_msg_type(MsgType.SEND_AUTH_INFO_ERROR)
                .with_ie('imsi', imsi)
                .with_ie('cause', GMMCause.IMSI_UNKNOWN.value)
                .build(),
            )
        except Exception as e:
            await self._logger.logAsync(service='GSUP', level='ERROR', message=f"Error handling GSUP message: {str(e)}, {traceback.format_exc()}")
            await self._send_gsup_response(peer, GsupMessageBuilder().with_msg_type(
                MsgType.SEND_AUTH_INFO_ERROR).with_ie('imsi', imsi).build())
