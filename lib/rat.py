# PyHSS RAT Technology restriction handling
# Copyright 2025 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
try:
    from enum import StrEnum
except ImportError:
    # For Python versions < 3.11, use the strenum package
    from strenum import StrEnum

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
