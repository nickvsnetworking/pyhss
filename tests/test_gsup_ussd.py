# PyHSS GSUP USSD Controller tests
# Copyright 2026 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import binascii
from collections import OrderedDict
from unittest import TestCase
from unittest.mock import AsyncMock, MagicMock, patch

from osmocom.gsup.message import GsupMessage, MsgType
from smspdudecoder.codecs import GSM

from gsup.controller.ss import USSD, SSController, UnknownUSSD
from gsup.protocol.gsup_msg import GsupMessageBuilder, GsupMessageUtil

DEFAULT_TARGETS = {"*#100#": "Your MSISDN is: %msisdn%",
                   "*#101#": "Your IMSI is: %imsi%"}
DEFAULT_TARGETS_SINGLE = {"*#100#": "Your MSISDN is: %msisdn%"}
DEFAULT_SUBSCRIBER = {"imsi": "262423403000001", "msisdn": "12345"}


def _build_controller(targets, subscriber_data=None):
    """Create an SSController with response capture for testing."""
    logger = MagicMock()
    logger.logAsync = AsyncMock()
    database = MagicMock()
    if subscriber_data is not None:
        database.Get_Subscriber.return_value = subscriber_data
    controller = SSController(logger=logger, database=database)
    controller.targets = targets
    controller._sent_responses = []
    original_send = controller._send_gsup_response
    async def capture_send(peer, response):
        controller._sent_responses.append(response)
        await original_send(peer, response)
    controller._send_gsup_response = capture_send
    return controller


def _make_peer():
    peer = MagicMock()
    peer.writer = AsyncMock()
    peer.writer.write = MagicMock()
    peer.writer.drain = AsyncMock()
    return peer


def _get_ie(response, name):
    """Extract an IE dict from a GsupMessage by name."""
    return next((ie for ie in response.to_dict()["ies"] if name in ie), None)


def _make_message_dict(imsi="262423403000001", session_state="start", session_id=1,
                       supplementary_service_info=None):
    """Build a minimal GsupMessage dict for testing."""
    ies = []
    if imsi is not None:
        ies.append({"imsi": imsi})
    if session_state is not None:
        ies.append({"session_state": session_state})
    if session_id is not None:
        ies.append({"session_id": session_id})
    if supplementary_service_info is not None:
        ies.append({"supplementary_service_info": supplementary_service_info})
    return {"msg_type": "PROC_SS_REQUEST", "ies": ies}


def _encode_ussd_invoke(invoke_id, ussd_code):
    """Encode a USSD invoke Component using the same USSD schema as SSController."""
    comp = USSD.modules["USSD"]["Component"]
    ussd_arg = USSD.modules["USSD"]["USSD-Arg"]
    ussd_data = OrderedDict()
    ussd_data["ussd-DataCodingScheme"] = b"\x0f"
    ussd_data["ussd-String"] = binascii.a2b_hex(GSM().encode(ussd_code))
    invokeparameter = ussd_arg.encode(ussd_data)
    invoke_data = OrderedDict()
    invoke_data["invokeID"] = invoke_id
    invoke_data["opCode"] = ("localValue", 59)
    invoke_data["invokeparameter"] = invokeparameter
    return comp.encode(("invoke", invoke_data))


def _decode_ussd_response(ussd_encoded):
    """Decode the USSD-Response from a GSUP supplementary_service_info IE."""
    _, data = USSD.decode("Component", ussd_encoded)
    ussd_arg = USSD.decode("USSD-Arg", data["resultretres"]["returnparameter"])
    return GSM().decode(str(binascii.b2a_hex(ussd_arg["ussd-String"]), "utf-8"), strip_padding=True)


class TestUSSDControllerInit(TestCase):
    """Test SSController initialization with different configs."""

    @patch("gsup.controller.ss.config")
    def test_no_ussd_config(self, mock_config):
        mock_config.get.return_value = {}
        controller = SSController(logger=None, database=None)
        self.assertEqual(controller.targets, {})

    @patch("gsup.controller.ss.config")
    def test_empty_codes(self, mock_config):
        mock_config.get.return_value = {"gsup": {"ussd": {"codes": []}}}
        controller = SSController(logger=None, database=None)
        self.assertEqual(controller.targets, {})

    @patch("gsup.controller.ss.config")
    def test_with_ussd_config(self, mock_config):
        ussd_config = {
            "codes": [
                {"code": "*#100#", "msg": "MSISDN: %msisdn%"},
                {"code": "*#101#", "msg": "IMSI: %imsi%"},
            ],
        }
        mock_config.get.return_value = {"gsup": {"ussd": ussd_config}}
        controller = SSController(logger=None, database=None)
        expected_targets = {"*#100#": "MSISDN: %msisdn%",
                            "*#101#": "IMSI: %imsi%"}
        self.assertEqual(controller.targets, expected_targets)


class TestHandleMessage(TestCase):
    """Test handle_message entry point."""

    def _build(self):
        return _build_controller(
            DEFAULT_TARGETS, DEFAULT_SUBSCRIBER)

    def test_handle_message_missing_imsi(self):
        controller = self._build()
        peer = _make_peer()
        message = GsupMessage.from_dict(_make_message_dict(imsi=None))
        asyncio.run(controller.handle_message(peer, message))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertIsNotNone(_get_ie(response, "session_state"))
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        self.assertIsNone(_get_ie(response, "supplementary_service_info"))

    def test_handle_message_missing_session_state(self):
        controller = self._build()
        peer = _make_peer()
        message = GsupMessage.from_dict(_make_message_dict(session_state=None))
        asyncio.run(controller.handle_message(peer, message))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertIsNotNone(_get_ie(response, "session_state"))
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        self.assertIsNone(_get_ie(response, "supplementary_service_info"))

    def test_handle_message_missing_session_id(self):
        controller = self._build()
        peer = _make_peer()
        message = GsupMessage.from_dict(_make_message_dict(session_id=None))
        asyncio.run(controller.handle_message(peer, message))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertIsNotNone(_get_ie(response, "session_state"))
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        self.assertIsNone(_get_ie(response, "supplementary_service_info"))

    def test_handle_message_missing_session_id_with_component(self):
        """A missing session_id IE must answer with dataMissing (35);
        the invoke ID is recovered from the component."""
        controller = self._build()
        peer = _make_peer()
        ussd_data = _encode_ussd_invoke(4, "*#100#")
        message = GsupMessage.from_dict(
            _make_message_dict(session_id=None, supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))

        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        op, data = USSD.decode("Component", ss_info_ie["supplementary_service_info"])
        self.assertEqual(op, "returnError")
        self.assertEqual(data["invokeID"], 4)
        self.assertEqual(data["errorCode"], ("localValue", 35))

    def test_handle_message_subscriber_not_found(self):
        controller = self._build()
        peer = _make_peer()
        controller._database.Get_Subscriber.return_value = None
        ussd_data = _encode_ussd_invoke(1, "*#100#")
        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertIsNotNone(_get_ie(response, "session_state"))
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        op, data = USSD.decode("Component", ss_info_ie["supplementary_service_info"])
        self.assertEqual(op, "returnError")
        self.assertEqual(data["invokeID"], 1)
        self.assertEqual(data["errorCode"], ("localValue", 1))
        controller._database.Get_Subscriber.assert_called_with(imsi="262423403000001")

    def test_handle_message_known_code_msisdn(self):
        controller = self._build()
        peer = _make_peer()
        ussd_data = _encode_ussd_invoke(1, "*#100#")
        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        # Verify MSISDN was substituted in the USSD response
        decoded_response = _decode_ussd_response(ss_info_ie["supplementary_service_info"])
        self.assertEqual(decoded_response, "Your MSISDN is: 12345")

    def test_handle_message_known_code_imsi(self):
        controller = self._build()
        peer = _make_peer()
        ussd_data = _encode_ussd_invoke(1, "*#101#")
        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        # Verify IMSI was substituted in the USSD response
        decoded_response = _decode_ussd_response(ss_info_ie["supplementary_service_info"])
        self.assertEqual(decoded_response, "Your IMSI is: 262423403000001")

    def test_handle_message_unknown_code(self):
        """An unknown USSD code must end the session with a MAP
        returnError carrying ss-NotAvailable (18)."""
        controller = self._build()
        peer = _make_peer()
        ussd_data = _encode_ussd_invoke(1, "*#999#")
        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        op, data = USSD.decode("Component", ss_info_ie["supplementary_service_info"])
        self.assertEqual(op, "returnError")
        self.assertEqual(data["invokeID"], 1)
        self.assertEqual(data["errorCode"], ("localValue", 18))

    def test_handle_message_invalid_opcode_sends_return_error(self):
        """An unsupported opCode must end the session with a MAP
        returnError carrying facilityNotSupported (21)."""
        controller = self._build()
        peer = _make_peer()
        # Build an invoke with opCode 19 (processUnstructuredSS-Data)
        comp = USSD.modules["USSD"]["Component"]
        ussd_arg = USSD.modules["USSD"]["USSD-Arg"]
        arg = OrderedDict()
        arg["ussd-DataCodingScheme"] = b"\x0f"
        arg["ussd-String"] = binascii.a2b_hex(GSM().encode("*#100#"))
        invoke = OrderedDict()
        invoke["invokeID"] = 5
        invoke["opCode"] = ("localValue", 19)
        invoke["invokeparameter"] = ussd_arg.encode(arg)
        ussd_data = comp.encode(("invoke", invoke))

        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))

        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        op, data = USSD.decode("Component", ss_info_ie["supplementary_service_info"])
        self.assertEqual(op, "returnError")
        self.assertEqual(data["invokeID"], 5)
        self.assertEqual(data["errorCode"], ("localValue", 21))

    def test_handle_message_db_error_sends_system_failure(self):
        """A generic exception must end the session with a MAP
        returnError carrying systemFailure (34)."""
        controller = self._build()
        peer = _make_peer()
        controller._database.Get_Subscriber.side_effect = RuntimeError("db down")
        ussd_data = _encode_ussd_invoke(7, "*#100#")
        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))

        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        op, data = USSD.decode("Component", ss_info_ie["supplementary_service_info"])
        self.assertEqual(op, "returnError")
        self.assertEqual(data["invokeID"], 7)
        self.assertEqual(data["errorCode"], ("localValue", 34))

    def test_handle_message_unrecoverable_invoke_id_sends_bare_response(self):
        """When the invoke ID cannot be recovered from garbage data,
        the response must still end the session (bare end-session)."""
        controller = self._build()
        peer = _make_peer()
        controller._database.Get_Subscriber.side_effect = RuntimeError("db down")
        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=b"garbage"))
        asyncio.run(controller.handle_message(peer, message))

        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        self.assertIsNone(_get_ie(response, "supplementary_service_info"))

    def test_handle_message_incoming_return_error_ends_session_quietly(self):
        """A returnError from the MS concludes the operation; it must not
        be answered with a counter-error (TCAP semantics)."""
        controller = self._build()
        peer = _make_peer()
        comp = USSD.modules["USSD"]["Component"]
        error = OrderedDict()
        error["invokeID"] = 3
        error["errorCode"] = ("localValue", 34)
        ussd_data = comp.encode(("returnError", error))

        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))

        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        self.assertIsNone(_get_ie(response, "supplementary_service_info"))

    def test_handle_message_return_result_not_last_ends_session_quietly(self):
        """A returnResultNotLast must also end the session without a
        counter-error."""
        controller = self._build()
        peer = _make_peer()
        comp = USSD.modules["USSD"]["Component"]
        result = OrderedDict()
        result["invokeID"] = 9
        ussd_data = comp.encode(("returnResultNotLast", result))

        message = GsupMessage.from_dict(_make_message_dict(supplementary_service_info=ussd_data))
        asyncio.run(controller.handle_message(peer, message))

        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        self.assertIsNone(_get_ie(response, "supplementary_service_info"))


class TestHandleUSSD(TestCase):
    """Test handle_ussd internal logic."""

    def test_handle_ussd_valid_invoke(self):
        controller = _build_controller(
            DEFAULT_TARGETS_SINGLE)
        peer = _make_peer()
        subscriber = {"imsi": "262423403000001", "msisdn": "12345"}
        message = _make_message_dict()
        ussd_data = _encode_ussd_invoke(42, "*#100#")
        asyncio.run(controller.handle_ussd(peer, message, subscriber, ussd_data))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        decoded_response = _decode_ussd_response(ss_info_ie["supplementary_service_info"])
        self.assertEqual(decoded_response, "Your MSISDN is: 12345")

    def test_handle_ussd_invalid_op_code(self):
        controller = _build_controller(
            DEFAULT_TARGETS_SINGLE)
        peer = _make_peer()
        subscriber = {"imsi": "262423403000001", "msisdn": "12345"}
        message = _make_message_dict()
        # Encode a valid invoke with a different opCode (not 59)
        comp = USSD.modules["USSD"]["Component"]
        ussd_arg = USSD.modules["USSD"]["USSD-Arg"]
        ussd_data_field = OrderedDict()
        ussd_data_field["ussd-DataCodingScheme"] = b"\x0f"
        ussd_data_field["ussd-String"] = binascii.a2b_hex(GSM().encode("*#999#"))
        invokeparameter = ussd_arg.encode(ussd_data_field)
        invoke_data = OrderedDict()
        invoke_data["invokeID"] = 1
        invoke_data["opCode"] = ("localValue", 19)  # processUnstructuredSS-Data, not 59
        invoke_data["invokeparameter"] = invokeparameter
        ussd_data = comp.encode(("invoke", invoke_data))
        with self.assertRaises(UnknownUSSD):
            asyncio.run(controller.handle_ussd(peer, message, subscriber, ussd_data))

    def test_handle_ussd_return_result_last(self):
        controller = _build_controller(
            DEFAULT_TARGETS_SINGLE)
        peer = _make_peer()
        subscriber = {"imsi": "262423403000001", "msisdn": "12345"}
        message = _make_message_dict()
        # Encode a returnResultLast Component using the same method as encode_map_component
        component = SSController.encode_map_component(1, "test")
        ussd_data = component
        asyncio.run(controller.handle_ussd(peer, message, subscriber, ussd_data))
        # Should send end_session_response response (pass-through case)
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertIsNotNone(_get_ie(response, "session_state"))
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")

    def test_handle_ussd_seven_char_code_with_cr_padding(self):
        """A 7-septet USSD code is CR-padded by the phone (GSM 03.38);
        the padding must be stripped before the code lookup."""
        controller = _build_controller({"*#1234#": "It works"})
        peer = _make_peer()
        subscriber = {"imsi": "262423403000001", "msisdn": "12345"}
        message = _make_message_dict()
        # Simulate the phone: 7 septets + CR padding septet
        ussd_data = _encode_ussd_invoke(1, "*#1234#\r")
        asyncio.run(controller.handle_ussd(peer, message, subscriber, ussd_data))
        self.assertEqual(len(controller._sent_responses), 1)
        ss_info_ie = _get_ie(controller._sent_responses[0], "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        decoded_response = _decode_ussd_response(ss_info_ie["supplementary_service_info"])
        self.assertEqual(decoded_response, "It works")


class TestStaticMethods(TestCase):
    """Test static utility methods."""

    def test_end_session_response(self):
        message = _make_message_dict()
        response = SSController.end_session_response(message)
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertIsNotNone(_get_ie(response, "imsi"))
        self.assertEqual(_get_ie(response, "imsi")["imsi"], "262423403000001")
        self.assertIsNotNone(_get_ie(response, "session_id"))
        self.assertIsNotNone(_get_ie(response, "session_state"))
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")

    def test_end_session_response_missing_imsi(self):
        message = _make_message_dict(imsi=None)
        response = SSController.end_session_response(message)
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertIsNone(_get_ie(response, "imsi"))

    def test_gsup_from_ussd(self):
        message = _make_message_dict()
        ussd_encoded = b"\x00\x01\x02"
        response = SSController.gsup_from_ussd(message, ussd_encoded)
        self.assertEqual(response.msg_type, MsgType.PROC_SS_RESULT)
        self.assertEqual(_get_ie(response, "session_state")["session_state"], "end")
        self.assertEqual(_get_ie(response, "supplementary_service_info")["supplementary_service_info"], ussd_encoded)

    def test_encode_map_component_roundtrip(self):
        component = SSController.encode_map_component(42, "Your MSISDN is: 12345")
        op, data = USSD.decode("Component", component)
        self.assertEqual(op, "returnResultLast")
        self.assertEqual(data["invokeID"], 42)
        self.assertEqual(data["resultretres"]["opCode"], ("localValue", 59))
        # Verify the returnparameter can be decoded as USSD-Arg
        ussd_arg = USSD.decode("USSD-Arg", data["resultretres"]["returnparameter"])
        decoded_str = GSM().decode(str(binascii.b2a_hex(ussd_arg["ussd-String"]), "utf-8"))
        self.assertEqual(decoded_str, "Your MSISDN is: 12345")

    def test_encode_ussd_arg_roundtrip(self):
        answer = "Your IMSI is: 262423403000001"
        encoded = SSController.encode_ussd_arg(answer)
        ussd_arg = USSD.decode("USSD-Arg", encoded)
        decoded_str = GSM().decode(str(binascii.b2a_hex(ussd_arg["ussd-String"]), "utf-8"))
        self.assertEqual(decoded_str, answer)

class TestMessageLengths(TestCase):
    """Test GSM encoding/decoding with different message lengths.

    Regression test for a prior bug where a trailing '@' character caused
    5-digit numbers to return as 4-digit with truncated text.
    """

    def test_short_message(self):
        controller = _build_controller(
            DEFAULT_TARGETS, "Code not recognized.")
        peer = _make_peer()
        ussd_data = _encode_ussd_invoke(1, "*#100#")
        message = _make_message_dict()
        subscriber = {"imsi": "262423403000001", "msisdn": "12345"}
        asyncio.run(controller.handle_ussd(peer, message, subscriber, ussd_data))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        decoded_response = _decode_ussd_response(ss_info_ie["supplementary_service_info"])
        self.assertEqual(decoded_response, "Your MSISDN is: 12345")

    def test_long_message(self):
        controller = _build_controller(
            DEFAULT_TARGETS, "Code not recognized.")
        peer = _make_peer()
        ussd_data = _encode_ussd_invoke(1, "*#100#")
        message = _make_message_dict()
        subscriber = {"imsi": "262423403000001", "msisdn": "123456789012345"}
        asyncio.run(controller.handle_ussd(peer, message, subscriber, ussd_data))
        self.assertEqual(len(controller._sent_responses), 1)
        response = controller._sent_responses[0]
        ss_info_ie = _get_ie(response, "supplementary_service_info")
        self.assertIsNotNone(ss_info_ie)
        decoded_response = _decode_ussd_response(ss_info_ie["supplementary_service_info"])
        self.assertEqual(decoded_response, "Your MSISDN is: 123456789012345")

    def test_encode_ussd_arg_various_lengths(self):
        """Messages whose septet count % 8 == 7 must not decode with a
        trailing '@' (GSM 03.38 CR padding)."""
        for length in [1, 6, 7, 8, 15, 16, 23, 31, 32, 160]:
            msg = "A" * length
            encoded = SSController.encode_ussd_arg(msg)
            ussd_arg = USSD.decode("USSD-Arg", encoded)
            decoded = GSM().decode(str(binascii.b2a_hex(ussd_arg["ussd-String"]), "utf-8"),
                                   strip_padding=True)
            self.assertEqual(decoded, msg, f"Round-trip failed for length {length}")


class TestGsupMessageUtilCopyField(TestCase):
    """Test the copy_field_to_builder helper."""

    def test_copy_field_present(self):
        message = _make_message_dict()
        builder = GsupMessageBuilder().with_msg_type(MsgType.SEND_AUTH_INFO_RESULT)
        GsupMessageUtil.copy_field_to_builder("imsi", message, builder)
        response = builder.build()
        self.assertIsNotNone(_get_ie(response, "imsi"))
        self.assertEqual(_get_ie(response, "imsi")["imsi"], "262423403000001")

    def test_copy_field_missing(self):
        message = _make_message_dict(imsi=None)
        builder = GsupMessageBuilder().with_msg_type(MsgType.SEND_AUTH_INFO_RESULT)
        GsupMessageUtil.copy_field_to_builder("imsi", message, builder)
        response = builder.build()
        self.assertIsNone(_get_ie(response, "imsi"))


class TestGsupMessageBuilder(TestCase):
    """Test GsupMessageBuilder."""

    def test_build_without_msg_type_raises(self):
        builder = GsupMessageBuilder()
        with self.assertRaises(ValueError):
            builder.build()
