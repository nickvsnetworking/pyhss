# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# Copyright 2026 Lennart Rosam <hello@takuto.de>
# Copyright 2026 eta <eta@eta.st>
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import sys
import yaml
from pathlib import Path

from gsup.protocol.gsup_msg import GMMCause

config = None


def load_config():
    global config

    if "PYHSS_CONFIG" in os.environ:
        paths = [os.environ["PYHSS_CONFIG"]]
        if not os.path.exists(paths[0]):
            print(f"ERROR: PYHSS_CONFIG is set, but file does not exist: {paths[0]}")
            sys.exit(1)
    else:
        paths = [
            "/etc/pyhss/config.yaml",
            "/usr/share/pyhss/config.yaml",
            Path(__file__).resolve().parent.parent / "config.yaml",
        ]

    for path in paths:
        if os.path.exists(path):
            with open(path, "r") as stream:
                config = yaml.safe_load(stream)
            return

    print("ERROR: failed to find PyHSS config, tried these paths:")
    for path in paths:
        print(f" * {path}")
    sys.exit(1)


def validate_config():
    """Validate configuration values at startup.

    Refuses to start if config options have unexpected values,
    preventing silent misconfiguration. Add future validations here."""

    valid_reject_causes = {"IMSI_UNKNOWN", "ROAMING_NOT_ALLOWED"}
    reject_cause = config.get('hss', {}).get('roaming', {}).get('inbound', {}).get('reject_unknown_imsis_with', 'IMSI_UNKNOWN')
    if reject_cause not in valid_reject_causes:
        print(f"ERROR: invalid value for hss.roaming.inbound.reject_unknown_imsis_with: '{reject_cause}'. "
              f"Valid options are: {', '.join(sorted(valid_reject_causes))}")
        sys.exit(1)


load_config()
validate_config()


def get_unknown_subscriber_2g_reject_cause() -> GMMCause:
    if config.get('hss', {}).get('roaming', {}).get('inbound', {}).get('reject_unknown_imsis_with', 'IMSI_UNKNOWN') == 'ROAMING_NOT_ALLOWED':
        return GMMCause.ROAMING_NOTALLOWED
    else:
        return GMMCause.IMSI_UNKNOWN
