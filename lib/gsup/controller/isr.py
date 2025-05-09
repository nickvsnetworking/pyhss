"""
    PyHSS GSUP Insert Subscriber Data Request Controller
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

from osmocom.gsup.message import GsupMessage

from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.controller.ulr import ULRTransaction
from gsup.protocol.ipa_peer import IPAPeer
from logtool import LogTool


class ISRController(GsupController):
    def __init__(self, logger: LogTool, database: Database, ulr_transactions: Dict[str, ULRTransaction]):
        super().__init__(logger, database)
        self.__ulr_transactions = ulr_transactions

    async def handle_message(self, peer: IPAPeer, message: GsupMessage):
        if peer.name not in self.__ulr_transactions:
            raise ValueError(f"ULR Transaction for peer {peer.name} not found")
        transaction = self.__ulr_transactions[peer.name]
        if transaction.is_finished():
            raise ValueError(f"ULR Transaction for peer {peer.name} is already finished")

        await transaction.handle_insert_subscriber_data_response(message)