# PyHSS GSUP Noop Controller - A controller that does nothing for a given
# message (e.g. like an answer)
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
from osmocom.gsup.message import GsupMessage

from database import Database
from gsup.controller.abstract_controller import GsupController
from gsup.protocol.ipa_peer import IPAPeer
from logtool import LogTool


class NoopController(GsupController):
    def __init__(self, logger: LogTool, database: Database):
        super().__init__(logger, database)

    async def handle_message(self, peer: IPAPeer, message: GsupMessage):
        await self._logger.logAsync(service='GSUP', level='DEBUG', message=f"Nothing to do for {message.msg_type.name} from {peer}. Ignoring.")
