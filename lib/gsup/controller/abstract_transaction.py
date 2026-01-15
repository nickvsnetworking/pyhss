# PyHSS GSUP transaction base class
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import time
from abc import ABC

from osmocom.gsup.message import GsupMessage, MsgType

from baseModels import SubscriberInfo
from gsup.protocol.gsup_msg import GsupMessageBuilder


class AbstractTransaction(ABC):

    def __init__(self):
        self._started_at = time.monotonic()
        self._timeout_seconds = 10

    async def begin_invoke(self):
        pass

    async def continue_invoke(self, message: GsupMessage):
        pass

    def is_finished(self):
        pass

    def _is_timed_out(self):
        return (time.monotonic() - self._started_at) > self._timeout_seconds

    @staticmethod
    def _build_isd_request(subscriber_info: SubscriberInfo, cn_domain: str) -> GsupMessage:
        request_builder = (GsupMessageBuilder()
                           .with_msg_type(MsgType.INSERT_DATA_REQUEST)
                           .with_ie('imsi', subscriber_info.imsi)
                           .with_msisdn_ie(subscriber_info.msisdn)
                           )

        if cn_domain == 'ps':
            for _, apn in enumerate(subscriber_info.apns):
                request_builder.with_pdp_info_ie(apn['apn_id'], apn['ip_version'], apn['name'])

        request_builder.with_ie('cn_domain', cn_domain)

        return request_builder.build()

    @staticmethod
    def _validate_cn_domain(cn_domain: str):
        valid_domains = list(['ps', 'cs'])
        if not cn_domain in valid_domains:
            raise ValueError(f"CN domain must be one of: {', '.join(valid_domains)}")
