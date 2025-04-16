# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import inspect
from pathlib import Path

from klpbuild.klplib.ibs import IBS
from klpbuild.plugins.setup import setup_codestreams

CS = "15.6u0"
DEFAULT_DATA = {"cve": None, "lp_filter": CS, "lp_skips": None, "conf": None, "no_check": False}


def test_list_of_packages():
    # Check if the package gathering mechanism works
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    codestreams = setup_codestreams(lp, DEFAULT_DATA)
    assert len(IBS(lp, CS).get_cs_packages(codestreams, Path("random"))) > 0
