# Copyright 2025 Lennart Rosam <hello@takuto.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
from unittest import TestCase

from pyhss_config import config, validate_config


class ConfigValidationTest(TestCase):
    def setUp(self):
        import pyhss_config
        self._saved_config = dict(pyhss_config.config) if pyhss_config.config else {}

    def tearDown(self):
        import pyhss_config
        pyhss_config.config = self._saved_config

    def test_valid_reject_causes(self):
        """Valid reject cause values should pass validation."""
        import pyhss_config
        for value in ('IMSI_UNKNOWN', 'ROAMING_NOT_ALLOWED'):
            with self.subTest(value=value):
                pyhss_config.config = {
                    'hss': {
                        'roaming': {
                            'inbound': {
                                'reject_unknown_imsis_with': value
                            }
                        }
                    }
                }
                validate_config()

    def test_config_passes_with_empty_or_nested_missing(self):
        """Config should pass validation when nested keys are missing."""
        import pyhss_config
        for cfg in ({}, {'hss': {}}, {'hss': {'roaming': {}}}, {'hss': {'roaming': {'inbound': {}}}}):
            with self.subTest(config=cfg):
                pyhss_config.config = cfg
                validate_config()

    def test_invalid_value_raises(self):
        """Invalid value should cause sys.exit."""
        import pyhss_config
        pyhss_config.config = {
            'hss': {
                'roaming': {
                    'inbound': {
                        'reject_unknown_imsis_with': 'INVALID_CAUSE'
                    }
                }
            }
        }
        with self.assertRaises(SystemExit):
            validate_config()
