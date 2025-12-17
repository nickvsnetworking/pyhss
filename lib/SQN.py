# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import Optional


class SQN:
    def __init__(self, seq: int, ind: int, ind_bitlen: Optional[int]):
        # 3GPP TS 33.102 § C.3.2 suggests 5
        if not ind_bitlen:
            ind_bitlen = 5

        self.seq = seq
        self.ind = ind
        self.ind_bitlen = ind_bitlen

    @classmethod
    def from_sqn(cls, sqn: int, ind_bitlen: Optional[int]):
        # 3GPP TS 33.102 § C.3.2 suggests 5
        if not ind_bitlen:
            ind_bitlen = 5

        seq = sqn >> ind_bitlen

        bitmask = (1 << ind_bitlen) - 1
        ind = sqn & bitmask

        return SQN(seq, ind, ind_bitlen)

    def get(self):
        # FIXME: modulo for seq by max seq len

        # Modulo by ind_bitlen value range
        ind = self.ind
        ind &= (1 << self.ind_bitlen) - 1

        return (self.seq << self.ind_bitlen) + ind

    def __repr__(self):
        return f"SQN={self.get()}(SEQ={self.seq},IND={self.ind})"
