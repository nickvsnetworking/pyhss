# Copyright 2026 Sig-thd <siegfried.roedel@th-deg.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for framing inbound Diameter messages in DiameterService.readInboundData().

TCP is a byte stream: a read can end inside a Diameter message or contain several of them. Every entry that
readInboundData() puts on the shared queue has to be exactly one complete message, framed by the Message Length
field of the Diameter header (RFC 6733 section 3).
"""

import asyncio
import importlib
import itertools
import random
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

top_dir = Path(Path(__file__) / "../..").resolve()
sys.path.append(str(top_dir / "services"))
diameterService = importlib.import_module("diameterService")


class _Reader:
    """Stands in for asyncio.StreamReader: read() returns the given chunks one by one, then EOF."""

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.eof = False

    async def read(self, n):
        if self.chunks:
            return self.chunks.pop(0)
        self.eof = True
        return b""

    def at_eof(self):
        return self.eof


def _message(hop_by_hop, length):
    """A Diameter request (Device-Watchdog command code, zero-filled body) of the given total length."""
    header = (
        bytes([1])
        + length.to_bytes(3, "big")
        + bytes([0x80])
        + (280).to_bytes(3, "big")
        + bytes(4)
        + hop_by_hop.to_bytes(4, "big")
        + hop_by_hop.to_bytes(4, "big")
    )
    return header + bytes(length - len(header))


def _split(data, cuts):
    """Cut data at the given offsets."""
    bounds = [0, *cuts, len(data)]
    return [data[a:b] for a, b in itertools.pairwise(bounds)]


@pytest.fixture
def service():
    svc = diameterService.DiameterService()
    svc.logTool.logAsync = AsyncMock()
    return svc


def _read(service, chunks):
    """Run readInboundData() over the chunks; return its result, the hex strings it queued and the unread chunks."""
    reader = _Reader(chunks)

    async def run():
        service.sharedQueue = asyncio.Queue()
        result = await service.readInboundData(
            reader=reader, clientAddress="10.0.0.1", clientPort="3868", socketTimeout=1, coroutineUuid="test"
        )
        queued = []
        while not service.sharedQueue.empty():
            queued.append(service.sharedQueue.get_nowait().InboundHex)
        return result, queued, reader.chunks

    return asyncio.run(run())


@pytest.mark.parametrize(
    "cuts",
    [
        [10],  # inside the header of the first message
        [100],  # inside the body of the first message
        [120],  # exactly between the two messages
        [125, 130],  # the header of the second message spread over three reads
    ],
    ids=["header", "body", "boundary", "next-header"],
)
def test_messages_split_across_reads(service, cuts):
    messages = [_message(1, 120), _message(2, 64)]

    result, queued, unread = _read(service, _split(b"".join(messages), cuts))

    assert result is False  # the stand-in reader ends with EOF
    assert queued == [m.hex() for m in messages]
    assert unread == []


def test_several_messages_in_one_read(service):
    messages = [_message(i, 20 + 4 * i) for i in range(1, 6)]

    _, queued, _ = _read(service, [b"".join(messages)])

    assert queued == [m.hex() for m in messages]


def test_random_read_boundaries(service):
    rng = random.Random(4)
    messages = [_message(i, 20 + 4 * rng.randrange(0, 1000)) for i in range(200)]
    data = b"".join(messages)
    cuts = sorted(rng.sample(range(1, len(data)), 300))

    _, queued, _ = _read(service, _split(data, cuts))

    assert queued == [m.hex() for m in messages]


@pytest.mark.parametrize(
    "header",
    [
        bytes([2]) + (20).to_bytes(3, "big"),  # unknown version
        bytes([1]) + (12).to_bytes(3, "big"),  # length shorter than the header
    ],
    ids=["version", "length"],
)
def test_invalid_header_closes_connection(service, header):
    data = _message(1, 32) + header + bytes(16) + _message(2, 32)
    later = _message(3, 32)

    result, queued, unread = _read(service, [data, later])

    # The connection is closed at the invalid header: the message before it is queued, nothing after it is,
    # and the next read never happens.
    assert result is False
    assert queued == [_message(1, 32).hex()]
    assert unread == [later]
