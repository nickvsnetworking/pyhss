# PyHSS GSUP Insert Subscriber Data Request Controller
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
from enum import IntEnum
from typing import Dict, Callable, Awaitable, Optional

from osmocom.gsup.message import GsupMessage, MsgType

from baseModels import SubscriberInfo
from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.controller.abstract_transaction import AbstractTransaction
from gsup.controller.ulr import ULRTransaction
from gsup.protocol.ipa_peer import IPAPeer
from logtool import LogTool


class ISDTransaction(AbstractTransaction):
    class __TransactionState(IntEnum):
        BEGIN_STATE_INITIAL = 0
        ISD_REQUEST_SENT = 1
        END_STATE_ISR_RECEIVED = 2

    def __init__(self, subscriber_info: SubscriberInfo, peer: IPAPeer, cn_domain: str, callback_send_response: Callable[[IPAPeer, GsupMessage], Awaitable[None]]):
        super().__init__()
        self.__ipa_peer = peer
        self.__subscriber_info = subscriber_info
        self.__state = self.__TransactionState.BEGIN_STATE_INITIAL
        self.__cb_send_response = callback_send_response

        self._validate_cn_domain(cn_domain)
        self.__cn_domain = cn_domain

    async def begin_invoke(self):
        if self.__state != self.__TransactionState.BEGIN_STATE_INITIAL:
            raise ValueError("ISD Transaction already started")

        isd_request = self._build_isd_request(self.__subscriber_info, self.__cn_domain)
        await self.__cb_send_response(self.__ipa_peer, isd_request)
        self.__state = self.__TransactionState.ISD_REQUEST_SENT

    async def continue_invoke(self, message: GsupMessage):
        if self.__state != self.__TransactionState.ISD_REQUEST_SENT:
            raise ValueError("ISD Transaction not in ISD_REQUEST_SENT state")

        if message.msg_type != MsgType.INSERT_DATA_RESULT:
            raise ValueError(f"ISD transaction was not successful. Got: {message.msg_type}")

        self.__state = self.__TransactionState.END_STATE_ISR_RECEIVED

    def is_finished(self):
        if self._is_timed_out():
            return True

        return self.__state == self.__TransactionState.END_STATE_ISR_RECEIVED

class ISRController(GsupController):
    def __init__(self, logger: LogTool, database: Database, ulr_transactions: Dict[str, ULRTransaction], isd_transactions: Dict[str, ISDTransaction], all_peers: Dict[str, IPAPeer]):
        super().__init__(logger, database)
        self.__ulr_transactions = ulr_transactions
        self.__isd_transactions = isd_transactions
        self.__all_peers = all_peers

    async def handle_message(self, peer: IPAPeer, message: GsupMessage):
        transaction = self.__find_transaction_for_imsi(message, peer)
        if transaction.is_finished():
            raise ValueError(f"ULR Transaction for peer {peer.name} is already finished")

        await transaction.continue_invoke(message)

    def __find_transaction_for_imsi(self, message: GsupMessage, peer: IPAPeer) -> AbstractTransaction:
        if peer.name in self.__ulr_transactions:
            return self.__ulr_transactions[peer.name]
        if peer.name in self.__isd_transactions:
            return self.__isd_transactions[peer.name]
        raise ValueError(f"No transaction found for peer {peer.name} during message {message.msg_type}")

    async def handle_subscriber_update(self, subscriber_info: SubscriberInfo):
        for location, domain in [
            (subscriber_info.location_info_2g.msc, 'cs'),
            (subscriber_info.location_info_2g.vlr, 'cs'),
            (subscriber_info.location_info_2g.sgsn, 'ps'),
        ]:
            peer = self.__find_ipa_peer_by_id(location)
            if peer is not None and peer.name not in self.__isd_transactions:
                isd_transaction = ISDTransaction(subscriber_info, peer, domain, self._send_gsup_response)
                self.__isd_transactions[peer.name] = isd_transaction
                await isd_transaction.begin_invoke()


    def __find_ipa_peer_by_id(self, peer_id: Optional[str]) -> Optional[IPAPeer]:
        if peer_id is None:
            return None
        for peer in self.__all_peers.values():
            if peer.primary_id == peer_id:
                return peer
        return None
