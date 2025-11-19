"""
    PyHSS GSUP transaction base class
    Copyright (C) 2025  Lennart Rosam <hello@takuto.de>

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
from abc import ABC
from datetime import datetime

from osmocom.gsup.message import GsupMessage


class AbstractTransaction(ABC):

    def __init__(self):
        self._started_at = datetime.now()
        self._timeout_seconds = 10

    async def begin_invoke(self):
        pass

    async def continue_invoke(self, message: GsupMessage):
        pass

    def is_finished(self):
        pass

    def _is_timed_out(self):
        return (datetime.now() - self._started_at).seconds > self._timeout_seconds
