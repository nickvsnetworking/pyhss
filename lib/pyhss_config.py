"""
    Copyright (C) 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>

    SPDX-License-Identifier: AGPL-3.0-or-later

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import os
import sys
import yaml
from pathlib import Path

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


load_config()
