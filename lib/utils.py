import re


class InvalidIMSI(Exception):
    """validate_imsi may raise this exception"""


def validate_imsi(imsi):
    if not re.match(r'^\d{6,15}$', imsi):
        raise InvalidIMSI(f"IMSI is invalid: {imsi}")
