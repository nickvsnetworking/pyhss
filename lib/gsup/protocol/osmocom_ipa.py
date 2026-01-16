# This file was copied & modified from:
# https://gitea.osmocom.org/cellular-infrastructure/osmo-python-tests/src/tag/0.3.0/osmopy/twisted_ipa.py
# Copyright 2016-2018 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: GPL-3.0-or-later
import struct

class IPAError(RuntimeError):
    pass
class IPAUnknownTag(IPAError):
    pass

class IPA(object):
    """
    Stateless IPA protocol multiplexer: add/remove/parse (extended) header
    """
    version = "0.0.7"
    TCP_PORT_OML = 3002
    TCP_PORT_RSL = 3003
    # OpenBSC extensions: OSMO, MGCP_OLD
    PROTO = dict(RSL=0x00, CCM=0xFE, SCCP=0xFD, OML=0xFF, OSMO=0xEE, MGCP_OLD=0xFC)
    # ...OML Router Control, GSUP GPRS extension, Osmocom Authn Protocol
    EXT = dict(CTRL=0, MGCP=1, LAC=2, SMSC=3, ORC=4, GSUP=5, OAP=6, RSPRO=7)
    # OpenBSC extension: SCCP_OLD
    MSGT = dict(PING=0x00, PONG=0x01, ID_GET=0x04, ID_RESP=0x05, ID_ACK=0x06, SCCP_OLD=0xFF)
    _IDTAG = dict(SERNR=0, UNITNAME=1, LOCATION=2, TYPE=3, EQUIPVERS=4, SWVERSION=5, IPADDR=6, MACADDR=7, UNIT=8)
    CTRL_GET = 'GET'
    CTRL_SET = 'SET'
    CTRL_REP = 'REPLY'
    CTRL_ERR = 'ERROR'
    CTRL_TRAP = 'TRAP'
    CTRL_TRAP_ID = 0

    @staticmethod
    def _l(d, p):
        """
        Reverse dictionary lookup: return key for a given value
        """
        if p is None:
            return 'UNKNOWN'
        return list(d.keys())[list(d.values()).index(p)]

    @staticmethod
    def _tag(t, v):
        """
        Create TAG as TLV data
        """
        return struct.pack(">HB", len(v) + 1, t) + v

    def proto(self, p):
        """
        Lookup protocol name
        """
        return self._l(self.PROTO, p)

    def ext(self, p):
        """
        Lookup protocol extension name
        """
        return self._l(self.EXT, p)

    def msgt(self, p):
        """
        Lookup message type name
        """
        return self._l(self.MSGT, p)

    def idtag(self, p):
        """
        Lookup ID tag name
        """
        return self._l(self._IDTAG, p)

    def ext_name(self, proto, exten):
        """
        Return proper extension byte name depending on the protocol used
        """
        if self.PROTO['CCM'] == proto:
            return self.msgt(exten)
        if self.PROTO['OSMO'] == proto:
            return self.ext(exten)
        return None

    @staticmethod
    def add_header(data, proto, ext=None):
        """
        Add IPA header (with extension if necessary), data must be represented as bytes
        """
        if ext is None:
            return struct.pack(">HB", len(data) + 1, proto) + data
        return struct.pack(">HBB", len(data) + 1, proto, ext) + data

    def del_header(self, data):
        """
        Strip IPA protocol header correctly removing extension if present
        Returns data length, IPA protocol, extension (or None if not defined for a give protocol) and the data without header
        """
        if data is None or len(data) == 0:
            return None, None, None, None

        (dlen, proto) = struct.unpack('>HB', data[:3])
        if self.PROTO['OSMO'] == proto or self.PROTO['CCM'] == proto:  # there's extension which we have to unpack
            return struct.unpack('>HBB', data[:4]) + (data[4:],)  # length, protocol, extension, data
        return dlen, proto, None, data[3:]  # length, protocol, _, data

    def skip_traps(self, data):
        """
        Take one or more ctrl messages and data and return first non-TRAP message or None
        """
        if data is None or len(data) == 0:
            return None

        (head, tail) = self.split_combined(data)
        (length, _, _, payload) = self.del_header(head)
        # skip over broken messages as well as TRAPs
        if length == 0 or payload[:(length + 3)].decode('utf-8').startswith(self.CTRL_TRAP):
            return self.skip_traps(tail)

        return head

    def split_combined(self, data):
        """
        Split the data which contains multiple concatenated IPA messages into tuple (first, rest) where 'rest' contains
        remaining messages and 'first' is the single IPA message. No headers are stripped in 'first' or 'rest'.
        """
        if data is None or len(data) == 0:
            return None, None

        (length, _, _, _) = self.del_header(data)
        return data[:(length + 3)], data[(length + 3):]

    def tag_serial(self, data):
        """
        Make TAG for serial number
        """
        return self._tag(self._IDTAG['SERNR'], data)

    def tag_name(self, data):
        """
        Make TAG for unit name
        """
        return self._tag(self._IDTAG['UNITNAME'], data)

    def tag_loc(self, data):
        """
        Make TAG for location
        """
        return self._tag(self._IDTAG['LOCATION'], data)

    def tag_type(self, data):
        """
        Make TAG for unit type
        """
        return self._tag(self._IDTAG['TYPE'], data)

    def tag_equip(self, data):
        """
        Make TAG for equipment version
        """
        return self._tag(self._IDTAG['EQUIPVERS'], data)

    def tag_sw(self, data):
        """
        Make TAG for software version
        """
        return self._tag(self._IDTAG['SWVERSION'], data)

    def tag_ip(self, data):
        """
        Make TAG for IP address
        """
        return self._tag(self._IDTAG['IPADDR'], data)

    def tag_mac(self, data):
        """
        Make TAG for MAC address
        """
        return self._tag(self._IDTAG['MACADDR'], data)

    def tag_unit(self, data):
        """
        Make TAG for unit ID
        """
        return self._tag(self._IDTAG['UNIT'], data)

    def identity(self, unit=b'', mac=b'', location=b'', utype=b'', equip=b'', sw=b'', name=b'', serial=b''):
        """
        Make IPA IDENTITY tag list, by default returns empty concatenated bytes of tag list
        """
        return self.tag_unit(unit) + self.tag_mac(mac) + self.tag_loc(location) + self.tag_type(utype) + self.tag_equip(
            equip) + self.tag_sw(sw) + self.tag_name(name) + self.tag_serial(serial)

    def req_identity(self, id_tags=None):
        """
        Make IPA IDENTITY tag list, by default returns empty concatenated bytes of tag list
        """
        encoded = bytearray()
        if id_tags is None:
            id_tags = ['UNIT', 'MACADDR', 'TYPE', 'SWVERSION', 'LOCATION', 'UNITNAME']

        for tag in id_tags:
            if tag not in self._IDTAG:
                raise IPAUnknownTag(f"Unknown Tag given {tag}")
            encoded += bytearray([0x01, self._IDTAG[tag]])

        return encoded

    def ping(self):
        """
        Make PING message
        """
        return self.add_header(b'', self.PROTO['CCM'], self.MSGT['PING'])

    def pong(self):
        """
        Make PONG message
        """
        return self.add_header(b'', self.PROTO['CCM'], self.MSGT['PONG'])

    def id_ack(self):
        """
        Make ID_ACK CCM message
        """
        return self.add_header(b'', self.PROTO['CCM'], self.MSGT['ID_ACK'])

    def id_get(self):
        """
        Make ID_GET CCM message
        """
        return self.add_header(self.req_identity(), self.PROTO['CCM'], self.MSGT['ID_GET'])

    def id_resp(self, data):
        """
        Make ID_RESP CCM message
        """
        return self.add_header(data, self.PROTO['CCM'], self.MSGT['ID_RESP'])
