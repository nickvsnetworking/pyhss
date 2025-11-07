"""
    PyHSS GSUP Update Location Request Controller
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
from datetime import datetime
from enum import IntEnum
from typing import Callable, List, Dict, Optional
from osmocom.gsup.message import GsupMessage, MsgType

from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.protocol.gsup_msg import GsupMessageBuilder, GsupMessageUtil, GMMCause
from gsup.protocol.ipa_peer import IPAPeer, IPAPeerRole
from logtool import LogTool
from utils import validate_imsi, InvalidIMSI


class ULRSubscriberInfo:
    def __init__(self, apns: List[Dict[str, str]], msisdn: str, imsi: str):
        self.apns = apns
        self.msisdn = msisdn
        self.imsi = imsi


class ULRTransaction:
    class __TransactionState(IntEnum):
        BEGIN_STATE_INITIAL = 0
        ISD_REQUEST_SENT = 1
        END_STATE_ULR_SENT = 2
        END_STATE_CANCEL_LOCATION_SENT = 3

    def __init__(self, peer: IPAPeer, ulr: GsupMessage, cb_response_sender: Callable[[IPAPeer, GsupMessage], None],
                 cb_update_subscriber: Callable[[IPAPeer, str], Optional[IPAPeer]], subscriber_info: ULRSubscriberInfo):
        self.__peer = peer
        self.__ulr = ulr.to_dict()
        self.__subscriber_info = subscriber_info
        self.__cb_response_sender = cb_response_sender
        self.__cb_update_subscriber = cb_update_subscriber
        self.__insert_subscriber_data_response = None
        self.__state = self.__TransactionState.BEGIN_STATE_INITIAL
        self.__old_peer = None
        self.__timeout_seconds = 10
        self.__started_at = datetime.now()

    async def begin(self):
        if self.__state != self.__TransactionState.BEGIN_STATE_INITIAL:
            raise ValueError("ULR Transaction already started")

        await self.__send_isd_request()
        self.__state = self.__TransactionState.ISD_REQUEST_SENT

    async def handle_insert_subscriber_data_response(self, response: GsupMessage):
        if self.__state != self.__TransactionState.ISD_REQUEST_SENT:
            raise ValueError("ULR Transaction not in ISD_REQUEST_SENT state")

        self.__insert_subscriber_data_response = response
        await self.__handle_insert_subscriber_data_response()
        if self.__old_peer is not None and self.__old_peer.primary_id != self.__peer.primary_id:
            await self.__send_cancel_location_request()

    def is_finished(self):
        if self.__is_timed_out():
            return True

        if self.__state == self.__TransactionState.END_STATE_ULR_SENT:
            return self.__old_peer is None

        return self.__state == self.__TransactionState.END_STATE_CANCEL_LOCATION_SENT

    def __is_timed_out(self):
        return (datetime.now() - self.__started_at).seconds > self.__timeout_seconds

    async def __send_isd_request(self):
        request_builder = (GsupMessageBuilder()
                           .with_msg_type(MsgType.INSERT_DATA_REQUEST)
                           .with_ie('imsi', self.__subscriber_info.imsi)
                           .with_msisdn_ie(self.__subscriber_info.msisdn)
                           .with_ie('destination_name', '')
                           )

        cn_domain = GsupMessageUtil.get_first_ie_by_name('cn_domain', self.__ulr)
        if cn_domain == 'ps':
            for index, apn in enumerate(self.__subscriber_info.apns):
                request_builder.with_pdp_info_ie(index, apn['ip_version'], apn['name'])

        await self.__cb_response_sender(self.__peer, request_builder.build())

    async def __handle_insert_subscriber_data_response(self):
        imsi = GsupMessageUtil.get_first_ie_by_name('imsi', self.__insert_subscriber_data_response.to_dict())
        isd_success = self.__insert_subscriber_data_response.msg_type == MsgType.INSERT_DATA_RESULT
        if isd_success:
            self.__old_peer = self.__cb_update_subscriber(self.__peer, imsi)
        response_builder = (GsupMessageBuilder()
                            .with_ie('imsi', self.__subscriber_info.imsi)
                            .with_ie('destination_name', None)
                            )

        msg_type = MsgType.UPDATE_LOCATION_RESULT
        if self.__insert_subscriber_data_response.msg_type == MsgType.INSERT_DATA_ERROR:
            msg_type = MsgType.UPDATE_LOCATION_ERROR

        response_builder.with_msg_type(msg_type)
        response_builder.with_ie('imsi', self.__subscriber_info.imsi)
        response = response_builder.build()
        await self.__cb_response_sender(self.__peer, response)
        self.__state = self.__TransactionState.END_STATE_ULR_SENT

    async def __send_cancel_location_request(self):
        request_builder = (GsupMessageBuilder()
                           .with_msg_type(MsgType.LOCATION_CANCEL_REQUEST)
                           .with_ie('imsi', self.__subscriber_info.imsi)
                           .with_ie('destination_name', None)
                           )
        await self.__cb_response_sender(self.__old_peer, request_builder.build())
        self.__state = self.__TransactionState.END_STATE_CANCEL_LOCATION_SENT


class ULRController(GsupController):
    def __init__(self, logger: LogTool, database: Database, ulr_transactions: Dict[str, ULRTransaction], all_peers: Dict[str, IPAPeer]):
        super().__init__(logger, database)
        self.__ulr_transactions = ulr_transactions
        self.__all_ipa_peers = all_peers

    def __update_subscriber(self, peer: IPAPeer, imsi: str) -> Optional[IPAPeer]:
        old_id = self._database.update_hlr(imsi, peer.role, peer.primary_id)

        if old_id is None:
            return None

        for peer_name, peer in self.__all_ipa_peers.items():
            if self.__all_ipa_peers[peer_name].primary_id == old_id:
                return self.__all_ipa_peers[peer_name]
        return None

    async def handle_message(self, peer: IPAPeer, message: GsupMessage):
        imsi = None
        try:
            request_dict = message.to_dict()
            imsi = GsupMessageUtil.get_first_ie_by_name('imsi', request_dict)
            if imsi is None:
                raise ValueError(f"Missing IMSI in GSUP message from peer {peer}")
            validate_imsi(imsi)
            subscriber = self._database.Get_Subscriber(imsi=imsi)
            apns = list()
            msisdn = subscriber['msisdn']

            ip_version_to_str = {
                0: 'ipv4',
                1: 'ipv6',
                2: 'ipv4v6',
                3: 'ipv4v6',
            }

            for apn in apns:
                db_apn = self._database.Get_APN_by_Name(apn)
                ip_version_str = None
                if db_apn['ip_version'] in ip_version_to_str:
                    ip_version_str = ip_version_to_str[db_apn['ip_version']]
                apns.append({'name': apn, 'ip_version': ip_version_str})

            subscriber_info = ULRSubscriberInfo(apns, msisdn, imsi)


            transaction = ULRTransaction(peer, message, self._send_gsup_response, self.__update_subscriber, subscriber_info)
            self.__ulr_transactions[peer.name] = transaction
            await transaction.begin()
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
            builder = GsupMessageBuilder().with_msg_type(MsgType.UPDATE_LOCATION_ERROR)
            await self._logger.logAsync(service='GSUP', level='WARN', message=f"Subscriber not found: {imsi} {traceback.format_exc()}")
            if imsi is not None:
                builder.with_ie('imsi', imsi)
            builder.with_ie('cause', GMMCause.IMSI_UNKNOWN.value)
            await self._send_gsup_response(peer, builder.build())
        except Exception as e:
            await self._logger.logAsync(service='GSUP', level='ERROR', message=f"Error handling GSUP message: {str(e)}, {traceback.format_exc()}")
            if imsi is not None:
                await self._send_gsup_response(peer, GsupMessageBuilder().with_msg_type(
                    MsgType.UPDATE_LOCATION_ERROR).with_ie('imsi', imsi).build())
            await self._send_gsup_response(peer, GsupMessageBuilder().with_msg_type(
                MsgType.UPDATE_LOCATION_ERROR).build())
