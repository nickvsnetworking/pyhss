# PyHSS GSUP Request Controller base class
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
from abc import abstractmethod, ABC

from osmocom.gsup.message import GsupMessage

from database import Database
from gsup.protocol.ipa_peer import IPAPeer
from gsup.protocol.osmocom_ipa import IPA
from logtool import LogTool


class GsupController(ABC):
    def __init__(self, logger: LogTool, database: Database):
        self._logger = logger
        self._database = database
        self._ipa = IPA()

    @abstractmethod
    async def handle_message(self, peer: IPAPeer, message: GsupMessage):
        pass

    async def _send_gsup_response(self, peer: IPAPeer, response: GsupMessage):
        data = response.to_bytes()
        data = IPA.add_header(data, self._ipa.PROTO['OSMO'], self._ipa.EXT['GSUP'])
        peer.writer.write(data)
        await peer.writer.drain()
