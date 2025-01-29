# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela

import pytest

from klpbuild.klplib.codestream import Codestream

def test_wrong_cs_filter():
    with pytest.raises(ValueError, match=r"Filter regexp error!"):
        Codestream.from_cs("wrong-filter")
