# PyHSS GSUP SS Controller
# Copyright 2025-2026 Alexander Couzens <lynxis@fe80.eu>
# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later

import binascii
import traceback
from collections import OrderedDict
from pathlib import Path

import asn1tools
from gsup.controller.abstract_controller import GsupController
from gsup.protocol.gsup_msg import GsupMessageBuilder, GsupMessageUtil
from osmocom.gsup.message import MsgType
from pyhss_config import config
from smspdudecoder.codecs import GSM

# GSM MAP local error codes (see GSMMAPLocalErrorcode in ussd.asn1)
MAP_ERR_UNKNOWN_SUBSCRIBER = 1
MAP_ERR_FACILITY_NOT_SUPPORTED = 21
MAP_ERR_SS_NOT_AVAILABLE = 18
MAP_ERR_SYSTEM_FAILURE = 34
MAP_ERR_DATA_MISSING = 35
MAP_ERR_UNEXPECTED_DATA_VALUE = 36


class USSDError(RuntimeError):
    """USSD handling failed.

    Carries the GSM MAP local error code to return to the MS and,
    when known, the TCAP invoke ID of the failed operation.
    """

    def __init__(self, message, error_code=MAP_ERR_SYSTEM_FAILURE, invoke_id=None):
        super().__init__(message)
        self.error_code = error_code
        self.invoke_id = invoke_id


class UnknownUSSD(USSDError):
    """Unknown USSD message"""


asn1path = Path(__file__).with_name("ussd.asn1").resolve()
USSD = asn1tools.compile_files([str(asn1path)])


class SSController(GsupController):
    def __init__(self, logger, database):
        super().__init__(logger, database)

        ussd_config = config.get("hss", {}).get("gsup", {}).get("ussd", {})
        if not ussd_config or not ussd_config.get("codes", []):
            self.targets = {}
        else:
            ussd_targets = ussd_config.get("codes", [])
            self.targets = {code["code"]: code["msg"] for code in ussd_targets}

    @staticmethod
    def end_session_response(message: dict):
        """Generate a session-end response by reusing fields from the request."""
        response = GsupMessageBuilder().with_msg_type(MsgType.PROC_SS_RESULT)

        GsupMessageUtil.copy_field_to_builder("imsi", message, response)
        GsupMessageUtil.copy_field_to_builder("session_id", message, response)

        return response.with_ie("session_state", "end").build()

    @staticmethod
    def gsup_from_ussd(message: dict, ussd_encoded: bytes):
        """Generate a full GSUP message"""
        response = GsupMessageBuilder().with_msg_type(MsgType.PROC_SS_RESULT)

        GsupMessageUtil.copy_field_to_builder("imsi", message, response)
        GsupMessageUtil.copy_field_to_builder("session_id", message, response)

        return response.with_ie("session_state", "end").with_ie("supplementary_service_info", ussd_encoded).build()

    @staticmethod
    def encode_ussd_arg(answer: str) -> bytes:
        """
        Encode USSD-Arg of MAP into bytes

        OrderedDict([('ussd-DataCodingScheme', b'\x0f'),
             ('ussd-String', b'\xaaQ\x0c\x06\x1b\x01')])
        """
        # GSM 03.38: when 7 spare bits remain in the last octet, pad with
        # a CR septet so the receiver does not decode the padding as '@'.
        septets = sum(2 if char in GSM.ALPHABET_EXT.values() else 1 for char in answer)
        if septets % 8 == 7:
            answer += "\r"

        attr = USSD.modules["USSD"]["USSD-Arg"]
        data = OrderedDict()
        data["ussd-DataCodingScheme"] = b"\x0f"
        data["ussd-String"] = binascii.a2b_hex(GSM().encode(answer))

        return attr.encode(data)

    @staticmethod
    def encode_map_component(invoke_id: int, answer: str):
        """
        Encode a MAP returnResultLast component.

        The result should look like this:
            ('returnResultLast',
                OrderedDict(
                  ('invokeID', 1),
                  ('resultretres',
                        OrderedDict(('opCode', ('localValue', 59)),
                                ('returnparameter',
                                 bytearray(b'0\x1e\x04\x01\x0f\x04\x19\xd9w]\x0eJ'
                                           b'6\xa7IPz\x0e\x92\xd9d4\x99\xed'
                                           b'F\xbb\xe1f0\x99\xad\x06'))))))
        """
        comp = USSD.modules["USSD"]["Component"]
        outer = OrderedDict()
        outer["invokeID"] = invoke_id

        inner = OrderedDict()
        inner["opCode"] = ("localValue", 59)
        inner["returnparameter"] = SSController.encode_ussd_arg(answer)
        outer["resultretres"] = inner

        answer = comp.encode(("returnResultLast", outer))
        return answer

    @staticmethod
    def encode_error_component(invoke_id: int, error_code: int) -> bytes:
        """Encode a MAP returnError component."""
        comp = USSD.modules["USSD"]["Component"]
        error = OrderedDict()
        error["invokeID"] = invoke_id
        error["errorCode"] = ("localValue", error_code)
        return comp.encode(("returnError", error))

    @staticmethod
    def _peek_invoke_id(ussd_data):
        """Best-effort extraction of the invoke ID for error reporting."""
        if ussd_data is None:
            return None
        try:
            _, data = USSD.decode("Component", ussd_data)
            return data.get("invokeID") if isinstance(data, dict) else None
        except Exception:
            return None

    async def _send_error(self, peer, message, invoke_id, error_code):
        """End the session; attach a MAP returnError when possible."""
        if invoke_id is not None:
            component = self.encode_error_component(invoke_id, error_code)
            response = self.gsup_from_ussd(message, component)
        else:
            response = self.end_session_response(message)
        await self._send_gsup_response(peer, response)

    async def handle_ussd(self, peer, message, subscriber, ussd_data):
        op, data = USSD.decode("Component", ussd_data)
        if op == "invoke":
            if data["opCode"] != ("localValue", 59):
                raise UnknownUSSD(
                    f"Invalid opCode in invoke {data}",
                    error_code=MAP_ERR_FACILITY_NOT_SUPPORTED,
                    invoke_id=data["invokeID"],
                )

            invoke_id = data["invokeID"]
            ussd = USSD.decode("USSD-Arg", data["invokeparameter"])
            target = GSM().decode(str(binascii.b2a_hex(ussd["ussd-String"]), "utf-8"), strip_padding=True)
            await self._logger.logAsync(service="GSUP", level="INFO", message=f"Received USSD request {target}")

            if target not in self.targets:
                raise UnknownUSSD(
                    f"Unknown USSD code: {target}",
                    error_code=MAP_ERR_SS_NOT_AVAILABLE,
                    invoke_id=invoke_id,
                )

            ussd_response = self.targets[target]
            if "%imsi%" in ussd_response:
                ussd_response = ussd_response.replace("%imsi%", subscriber["imsi"])
            if "%msisdn%" in ussd_response:
                ussd_response = ussd_response.replace("%msisdn%", subscriber["msisdn"])

            component = self.encode_map_component(invoke_id, ussd_response)
            response = self.gsup_from_ussd(message, component)
            await self._send_gsup_response(peer, response)
            return
        elif op in ("returnResultLast", "returnResultNotLast", "returnError"):
            # A result or error from the peer concludes the operation;
            # answering it with a counter-error would be wrong. Fall
            # through to a quiet end-session response.
            pass
        else:
            invoke_id = data.get("invokeID") if isinstance(data, dict) else None
            raise UnknownUSSD(
                f"Invalid class or constructed {op} with {data}",
                error_code=MAP_ERR_UNEXPECTED_DATA_VALUE,
                invoke_id=invoke_id,
            )

        response = self.end_session_response(message)
        await self._send_gsup_response(peer, response)

    async def handle_message(self, peer, message):
        message = message.to_dict()
        ussd_data = GsupMessageUtil.get_first_ie_by_name("supplementary_service_info", message)

        try:
            imsi = GsupMessageUtil.get_first_ie_by_name("imsi", message)
            if imsi is None:
                raise USSDError(
                    "IMSI not found in SS message",
                    error_code=MAP_ERR_DATA_MISSING,
                )

            # Currently, we only support non-continuous sessions
            session_state = GsupMessageUtil.get_first_ie_by_name("session_state", message)
            if session_state is None:
                raise USSDError(
                    "Session state not found in SS message",
                    error_code=MAP_ERR_DATA_MISSING,
                )

            session_id = GsupMessageUtil.get_first_ie_by_name("session_id", message)
            if session_id is None:
                raise USSDError(
                    "Session id not found in SS message",
                    error_code=MAP_ERR_DATA_MISSING,
                )

            subscriber = self._database.Get_Subscriber(imsi=imsi)
            if subscriber is None:
                raise USSDError(
                    f"No subscriber found for IMSI={imsi}",
                    error_code=MAP_ERR_UNKNOWN_SUBSCRIBER,
                )

            await self.handle_ussd(peer, message, subscriber, ussd_data)

        except USSDError as e:
            await self._logger.logAsync(
                service="GSUP",
                level="ERROR",
                message=f"Error while handling USSD from {peer}: {traceback.format_exc()}",
            )
            invoke_id = e.invoke_id if e.invoke_id is not None else self._peek_invoke_id(ussd_data)
            await self._send_error(peer, message, invoke_id, e.error_code)
        except Exception:
            await self._logger.logAsync(
                service="GSUP",
                level="ERROR",
                message=f"Error while handling USSD from {peer}: {traceback.format_exc()}",
            )
            await self._send_error(peer, message, self._peek_invoke_id(ussd_data), MAP_ERR_SYSTEM_FAILURE)
