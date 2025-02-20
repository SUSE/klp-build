# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect
import logging

from klpbuild.plugins.extractor import Extractor
from klpbuild.plugins.setup import setup
from klpbuild.klplib import utils


def test_detect_file_without_ftrace_support(caplog):
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.6u0"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": False,
        "archs" : [utils.ARCH],
        "cve": None,
        "conf": "CONFIG_SMP",
        "module" : "vmlinux",
        "file_funcs" : [["lib/seq_buf.c", "seq_buf_putmem_hex"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)


    with caplog.at_level(logging.WARNING):
        Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    assert "lib/seq_buf.o is not compiled with livepatch support (-pg flag)" in caplog.text
