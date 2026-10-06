# Copyright 2026 Sig-thd <siegfried.roedel@th-deg.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the order in which awaitBulkMessage() takes messages from a queue.

sendMessage() and sendBulkMessage() append to the right of the list (RPUSH). hssService takes inbound Diameter
requests with awaitBulkMessage(), which has to return them oldest first, in the order they were queued.
"""

import asyncio

import pytest
from messaging import RedisMessaging
from messagingAsync import RedisMessagingAsync

QUEUE = "diameter-inbound"
PREFIX = {"usePrefix": True, "prefixHostname": "test-queue-order", "prefixServiceName": "diameter"}
MESSAGES = [f"request-{i}" for i in range(5)]


@pytest.fixture
def redis_messaging(run_redis):
    messaging = RedisMessaging()
    messaging.deleteQueue(QUEUE, **PREFIX)
    yield messaging
    messaging.deleteQueue(QUEUE, **PREFIX)


def _messages(reply):
    """The messages of a BLMPOP reply ([key, [message, ...]]), decoded."""
    return [message.decode() for message in reply[1]]


def test_bulk_messages_oldest_first(redis_messaging):
    for message in MESSAGES:
        redis_messaging.sendMessage(QUEUE, message, **PREFIX)

    assert _messages(redis_messaging.awaitBulkMessage(QUEUE, **PREFIX)) == MESSAGES


def test_bulk_messages_oldest_first_across_calls(redis_messaging):
    for message in MESSAGES:
        redis_messaging.sendMessage(QUEUE, message, **PREFIX)

    assert _messages(redis_messaging.awaitBulkMessage(QUEUE, count=2, **PREFIX)) == MESSAGES[:2]
    assert _messages(redis_messaging.awaitBulkMessage(QUEUE, count=2, **PREFIX)) == MESSAGES[2:4]
    assert _messages(redis_messaging.awaitBulkMessage(QUEUE, count=2, **PREFIX)) == MESSAGES[4:]


def test_bulk_messages_oldest_first_async(redis_messaging):
    async def run():
        messaging = RedisMessagingAsync()
        try:
            await messaging.sendBulkMessage(QUEUE, MESSAGES, **PREFIX)
            return _messages(await messaging.awaitBulkMessage(QUEUE, **PREFIX))
        finally:
            await messaging.redisClient.close()

    assert asyncio.run(run()) == MESSAGES
