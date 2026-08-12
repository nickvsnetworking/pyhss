# Copyright 2026 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

import pytest


@pytest.mark.skip_packaging
def test_debian_control_runtime_deps():
    """Ensure the two "RUNTIME DEPS" blocks have the same contents."""
    control = Path(Path(__file__) / "../../debian/control").resolve()

    inside_block = False
    blocks = []

    with open(control) as f:
        for line in f:
            if "RUNTIME DEPS START" in line:
                assert inside_block is False
                inside_block = True
                blocks.append([])

            if inside_block:
                blocks[-1] += [line]

            if "RUNTIME DEPS END" in line:
                assert inside_block is True
                inside_block = False

    assert len(blocks) == 2, f"expected 2 RUNTIME DEPS blocks, found {len(blocks)}"
    assert blocks[0] == blocks[1]
