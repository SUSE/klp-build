# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza

import pytest

from klpbuild.plugins.scan import scan

# This CVE is already covered on all codestreams
def test_scan_all_cs_patched(caplog):
    with pytest.raises(SystemExit):
        scan("2022-48801", "", False, "")
    assert "All supported codestreams are already patched" not in caplog.text
