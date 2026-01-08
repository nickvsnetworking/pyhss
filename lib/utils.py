# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import re


class InvalidIMSI(Exception):
    """validate_imsi may raise this exception"""


def validate_imsi(imsi):
    if not re.match(r'^\d{6,15}$', imsi):
        raise InvalidIMSI(f"IMSI is invalid: {imsi}")
