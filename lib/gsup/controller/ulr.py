# PyHSS GSUP Update Location Request Controller
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
import traceback
from enum import IntEnum
from typing import Callable, Dict, Optional, Awaitable

from osmocom.gsup.message import GsupMessage, MsgType

from baseModels import SubscriberInfo
from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.controller.abstract_transaction import AbstractTransaction
from gsup.protocol.gsup_msg import GsupMessageBuilder, GsupMessageUtil, GMMCause
from gsup.protocol.ipa_peer import IPAPeer
from logtool import LogTool
from rat import RAT, SubscriberRATRestriction
from utils import validate_imsi, InvalidIMSI


class ULRError(ValueError):
    def __init__(self, message: str, gmm_cause: GMMCause):
        super().__init__(message)
        self.gmm_cause = gmm_cause
        self.message = message


class ULRTransaction(AbstractTransaction):
    class __TransactionState(IntEnum):
        BEGIN_STATE_INITIAL = 0
        ISD_REQUEST_SENT = 1
        END_STATE_ULR_SENT = 2
        END_STATE_CANCEL_LOCATION_SENT = 3

    def __init__(self, peer: IPAPeer, ulr: GsupMessage, cb_response_sender: Callable[[IPAPeer, GsupMessage], Awaitable[None]],
                 cb_update_subscriber: Callable[[IPAPeer, str], Optional[IPAPeer]], subscriber_info: SubscriberInfo):
        super().__init__()
        self.__peer = peer
        self.__ulr = ulr.to_dict()
        self.__subscriber_info = subscriber_info
        self.__cb_response_sender = cb_response_sender
        self.__cb_update_subscriber = cb_update_subscriber
        self.__insert_subscriber_data_response = None
        self.__state = self.__TransactionState.BEGIN_STATE_INITIAL
        self.__old_peer = None

    async def begin_invoke(self):
        if self.__state != self.__TransactionState.BEGIN_STATE_INITIAL:
            raise ValueError("ULR Transaction already started")

        cn_domain = GsupMessageUtil.get_first_ie_by_name('cn_domain', self.__ulr)
        self._validate_cn_domain(cn_domain)
        await self.__cb_response_sender(self.__peer, self._build_isd_request(self.__subscriber_info, cn_domain))
        self.__state = self.__TransactionState.ISD_REQUEST_SENT

    async def continue_invoke(self, response: GsupMessage):
        if self.__state != self.__TransactionState.ISD_REQUEST_SENT:
            raise ValueError("ULR Transaction not in ISD_REQUEST_SENT state")

        self.__insert_subscriber_data_response = response
        await self.__handle_insert_subscriber_data_response()
        if self.__old_peer is not None and self.__old_peer.primary_id != self.__peer.primary_id:
            await self.__send_cancel_location_request()

    def is_finished(self):
        if self._is_timed_out():
            return True

        if self.__state == self.__TransactionState.END_STATE_ULR_SENT:
            return self.__old_peer is None

        return self.__state == self.__TransactionState.END_STATE_CANCEL_LOCATION_SENT

    async def __handle_insert_subscriber_data_response(self):
        imsi = GsupMessageUtil.get_first_ie_by_name('imsi', self.__insert_subscriber_data_response.to_dict())
        isd_success = self.__insert_subscriber_data_response.msg_type == MsgType.INSERT_DATA_RESULT
        if isd_success:
            self.__old_peer = self.__cb_update_subscriber(self.__peer, imsi)
        response_builder = (GsupMessageBuilder()
                            .with_ie('imsi', self.__subscriber_info.imsi)
                            )

        msg_type = MsgType.UPDATE_LOCATION_RESULT
        if self.__insert_subscriber_data_response.msg_type == MsgType.INSERT_DATA_ERROR:
            msg_type = MsgType.UPDATE_LOCATION_ERROR

        response_builder.with_msg_type(msg_type)
        response = response_builder.build()
        await self.__cb_response_sender(self.__peer, response)
        self.__state = self.__TransactionState.END_STATE_ULR_SENT

    async def __send_cancel_location_request(self):
        request_builder = (GsupMessageBuilder()
                           .with_msg_type(MsgType.LOCATION_CANCEL_REQUEST)
                           .with_ie('imsi', self.__subscriber_info.imsi)
                           )
        await self.__cb_response_sender(self.__old_peer, request_builder.build())
        self.__state = self.__TransactionState.END_STATE_CANCEL_LOCATION_SENT


class ULRController(GsupController):
    def __init__(self, logger: LogTool, database: Database, ulr_transactions: Dict[str, ULRTransaction], all_peers: Dict[str, IPAPeer]):
        super().__init__(logger, database)
        self.__ulr_transactions = ulr_transactions
        self.__all_ipa_peers = all_peers
        self.__rat_restriction_checker = SubscriberRATRestriction(logger=self._logger, service='GSUP')

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
            try:
                validate_imsi(imsi)
            except InvalidIMSI as e:
                raise ULRError(f"Invalid IMSI: {imsi}", GMMCause.INV_MAND_INFO) from e

            rat_type = GsupMessageUtil.get_first_ie_by_name('current_rat_type', request_dict)

            # Check 2G / 3G by default but not 4G. Running 4G over GSUP with PyHSS is rare enough to
            # not warrant checking by default.
            rat_types_to_check = [RAT.GERAN, RAT.UTRAN]

            # Current RAT Type is a list for some reason. Maybe a bug in osmocom?
            if rat_type is not None:
                if rat_type[0] == 'geran':
                    rat_types_to_check = [RAT.GERAN]
                elif rat_type[0] == 'utran':
                    rat_types_to_check = [RAT.UTRAN]
                elif rat_type[0] == 'eutran':
                    rat_types_to_check = [RAT.EUTRAN]
                else:
                    await self._logger.logAsync(service="GSUP", level="WARN", message=f"Unknown RAT type received in ULR: {rat_type[0]}. Checking both 2G and 3G RAT restrictions")
            else:
                await self._logger.logAsync(service="GSUP", level="WARN", message="No RAT type received in ULR, checking both 2G and 3G RAT restrictions")

            try:
                subscriber_info = self._database.Get_Gsup_SubscriberInfo(imsi)
                subscriber = self._database.Get_Subscriber(imsi=imsi, get_attributes=True)
            except ValueError as e:
                raise ULRError(f"Subscriber not found: {imsi}", GMMCause.IMSI_UNKNOWN) from e

            for rat_type_to_check in rat_types_to_check:
                if not self.__rat_restriction_checker.is_rat_allowed(subscriber['attributes'], rat_type_to_check):
                    raise ULRError(f"RAT {rat_type_to_check.value} not allowed for subscriber {imsi}", GMMCause.NO_SUIT_CELL_IN_LA)

            transaction = ULRTransaction(peer, message, self._send_gsup_response, self.__update_subscriber, subscriber_info)
            self.__ulr_transactions[peer.name] = transaction
            await transaction.begin_invoke()
        except ULRError as e:
            await self._logger.logAsync(service='GSUP', level='WARN', message=e.message)
            await self._send_gsup_response(
                peer,
                GsupMessageBuilder().with_msg_type(MsgType.UPDATE_LOCATION_ERROR)
                .with_ie('imsi', imsi)
                .with_ie('cause', e.gmm_cause.value)
                .build()
            )
        except Exception as e:
            await self._logger.logAsync(service='GSUP', level='ERROR', message=f"Error handling GSUP message: {str(e)}, {traceback.format_exc()}")
            if imsi is not None:
                await self._send_gsup_response(peer, GsupMessageBuilder().with_msg_type(
                    MsgType.UPDATE_LOCATION_ERROR).with_ie('imsi', imsi).build())
            await self._send_gsup_response(peer, GsupMessageBuilder().with_msg_type(
                MsgType.UPDATE_LOCATION_ERROR).build())
