"""
    Copyright (C) 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>

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
from typing import Optional

class SQN:
    def __init__(self, value: int, ind_bitlen: Optional[int]):
        # 3GPP TS 33.102 § C.3.2 suggests 5
        if not ind_bitlen:
            ind_bitlen = 5

        self.value = value
        self.ind_bitlen = ind_bitlen

    def get_seq(self):
        return self.value >> self.ind_bitlen

    def get_ind(self):
        bitmask = (1 << self.ind_bitlen) - 1
        return self.value & bitmask

    def set_seq(self, seq: int):
        # FIXME: modulo for seq by max seq len
        self.value = (seq << self.ind_bitlen) + self.get_ind()

    def set_ind(self, ind: int):
        # Modulo by ind_bitlen value range
        ind &= (1 << self.ind_bitlen) - 1

        self.value = (self.get_seq() << self.ind_bitlen) + ind

    def inc_seq(self):
        self.set_seq(self.get_seq() + 1)

    def __repr__(self):
        return f"SQN={self.value}(SEQ={self.get_seq()},IND={self.get_ind()})"
