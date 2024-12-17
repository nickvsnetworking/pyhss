"""
    PyHSS IP Access Peer - Represents a peer in the IPA protocol
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

from asyncio import StreamReader, StreamWriter
from enum import IntEnum


class IPAPeerRole(IntEnum):
    SGSN = 0
    MSC = 1


class IPAPeer:
    SUPPORTED_IPA_TAGS = list(
        ['SERNR', 'UNITNAME', 'LOCATION', 'TYPE', 'EQUIPVERS', 'SWVERSION', 'IPADDR', 'MACADDR', 'UNIT'])
    _PRIMARY_ID_PREFERENCE = list(['MACADDR', 'UNIT'])
    _ROLE_PREFERENCE_TAGS = list(['TYPE', 'UNIT', 'UNITNAME'])

    def __init__(self, name: str, tags: dict, reader: StreamReader, writer: StreamWriter):
        self.name = name
        self.tags = tags
        self.primary_id = None
        self.role = None
        self.reader = reader
        self.writer = writer

        # Resolve the primary ID by preference
        for tag in self._PRIMARY_ID_PREFERENCE:
            if tag in tags:
                self.primary_id = tags[tag]
                break

        if self.primary_id is None:
            raise ValueError(
                "No primary ID found in the tags. Need at least one of: " + ', '.join(self._PRIMARY_ID_PREFERENCE))

        # Resolve role by tags
        for tag in self._ROLE_PREFERENCE_TAGS:
            if tag in tags:
                tag_val = tags[tag]
                if IPAPeerRole.MSC.name.lower() in tag_val.lower():
                    self.role = IPAPeerRole.MSC
                    break
                elif IPAPeerRole.SGSN.name.lower() in tag_val.lower():
                    self.role = IPAPeerRole.SGSN
                    break

        if self.role is None:
            raise ValueError(
                "Role not found in tags. 'sgsn' or 'msc' must appear in one of there tags: " + ', '.join(
                    self._ROLE_PREFERENCE_TAGS))
    def __str__(self):
        return f"[{self.name} ({self.role.name})]"