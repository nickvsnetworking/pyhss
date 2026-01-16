# PyHSS GSUP Message Builder - A factory class to create new GSUP Messages
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
from enum import Enum
from osmocom.gsup.message import MsgType, GsupMessage


class GsupMessageBuilder:
    def __init__(self):
        self.gsup_dict = dict()
        self.gsup_dict['ies'] = list()
        self.gsup_dict['msg_type'] = ""

    def with_msg_type(self, msg_type: MsgType):
        self.gsup_dict['msg_type'] = msg_type.name
        return self

    def with_ie(self, name: str, value, merge: bool = True):
        if 'ies' not in self.gsup_dict:
            self.gsup_dict['ies'] = []

        if merge:
            for ie in self.gsup_dict['ies']:
                if name in ie and isinstance(ie[name], list) and isinstance(value, dict):
                    ie[name].append(value)
                    return self
                elif name in ie and isinstance(ie[name], list) and isinstance(value, list):
                    ie[name].extend(value)
                    return self

        self.gsup_dict['ies'].append({
            name: value
        })
        return self

    def with_msisdn_ie(self, msisdn: str):
        ie = {
            'bcd_len': (len(msisdn) + 1) // 2,
            'digits': msisdn
        }
        return self.with_ie('msisdn', ie)

    def with_pdp_info_ie(self, pdp_ctx_id: int, pdp_type: str, apn_name: str):
        pdp_info = []

        pdp_info.append({
            'pdp_context_id': pdp_ctx_id
        })

        pdp_info.append({
            'pdp_address': {
                'address': None,
                'hdr': {
                    'pdp_type_nr': pdp_type,
                    'pdp_type_org': 'ietf'
                }
            }
        })

        pdp_info.append({
            'access_point_name': apn_name
        })

        return self.with_ie('pdp_info', pdp_info, False)

    def build(self) -> GsupMessage:
        if 'msg_type' == "":
            raise ValueError("msg_type is required")
        return GsupMessage.from_dict(self.gsup_dict)


class GsupMessageUtil:
    GSUP_MSG_IES = "ies"
    GSUP_MSG_IE_IMSI = "imsi"
    GSUP_MSG_IE_AUTH_TUPLE = "auth_tuple"

    @staticmethod
    def get_first_ie_by_name(ie_name: str, message: dict):
        for ie in message['ies']:
            if ie_name in ie:
                return ie[ie_name]
        return None

    @staticmethod
    def get_ies_by_name(ie_name: str, message: dict):
        ies = []
        for ie in message['ies']:
            if ie_name in ie:
                ies.append(ie)
        return ies


# 3GPP TS 24.008 Chapter 10.5.5.14 / Table 10.5.147
class GMMCause(Enum):
    IMSI_UNKNOWN = 0x02
    ILLEGAL_MS = 0x03
    IMEI_NOT_ACCEPTED = 0x05
    ILLEGAL_ME = 0x06
    GPRS_NOTALLOWED = 0x07
    GPRS_OTHER_NOTALLOWED = 0x08
    MS_ID_NOT_DERIVED = 0x09
    IMPL_DETACHED = 0x0a
    PLMN_NOTALLOWED = 0x0b
    LA_NOTALLOWED = 0x0c
    ROAMING_NOTALLOWED = 0x0d
    NO_GPRS_PLMN = 0x0e
    NO_SUIT_CELL_IN_LA = 0x0f
    MSC_TEMP_NOTREACH = 0x10
    NET_FAIL = 0x11
    MAC_FAIL = 0x14
    SYNC_FAIL = 0x15
    CONGESTION = 0x16
    GSM_AUTH_UNACCEPT = 0x17
    NOT_AUTH_FOR_CSG = 0x19
    SMS_VIA_GPRS_IN_RA = 0x1c
    NO_PDP_ACTIVATED = 0x28
    SEM_INCORR_MSG = 0x5f
    INV_MAND_INFO = 0x60
    MSGT_NOTEXIST_NOTIMPL = 0x61
    MSGT_INCOMP_P_STATE = 0x62
    IE_NOTEXIST_NOTIMPL = 0x63
    COND_IE_ERR = 0x64
    MSG_INCOMP_P_STATE = 0x65
    PROTO_ERR_UNSPEC = 0x6f
