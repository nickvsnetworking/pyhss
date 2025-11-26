"""
    PyHSS RAT Technology restriction handling
    Copyright (C) 2025  Lennart Rosam <hello@takuto.de>

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

from enum import StrEnum
from typing import Optional, Dict, List

from logtool import LogTool


class RAT(StrEnum):
    GERAN = "2g"
    UTRAN = "3g"
    EUTRAN = "4g"

class SubscriberRATRestriction:

    def __init__(self, logger: LogTool, service: str):
        self.logger = logger
        self.service = service

    def is_rat_allowed(self, subscriber_attributes: Optional[List[Dict[str, str]]], rat: RAT) -> bool:
        """
        Checks if the given RAT technology is allowed for the subscriber based on their restrictions.

        Args:
            subscriber_attributes: Subscriber attributes dictionary containing RAT restrictions.
            rat: The RAT technology to check.

        Returns:
            bool: True if the RAT is allowed, False otherwise.
        """

        if not subscriber_attributes:
            return True  # No restrictions, all RATs allowed

        rat_restriction_key = f"rat_restriction_{rat.value}"
        restriction_value = None
        for attr in subscriber_attributes:
            if attr.get("key") == rat_restriction_key:
                restriction_value = attr.get("value").lower()
                break

        if restriction_value is None:
            return True  # No specific restriction for this RAT, allowed by default

        known_rat_restriction_values = ["allowed", "forbidden"]
        if restriction_value not in known_rat_restriction_values:
            self.logger.log(service=self.service, level="WARNING", message=f"Unknown RAT restriction value '{restriction_value}' for key '{rat_restriction_key}'. Defaulting to allowed.")
            return True

        return restriction_value != "forbidden"
