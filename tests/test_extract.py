# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect
import logging

from klpbuild.extractor import Extractor
from klpbuild.plugins.setup import Setup
from klpbuild import utils


def test_detect_file_without_ftrace_support(caplog):
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.6u0"

    setup = Setup(lp)
    ffuncs = Setup.setup_file_funcs("CONFIG_SMP", "vmlinux", [["lib/seq_buf.c", "seq_buf_putmem_hex"]],
                                    [], [])
    codestreams = setup.setup_codestreams({"cve": None, "conf": "CONFIG_SMP",
                                          "no_check": False, "lp_filter": cs, "lp_skips": None})
    setup.setup_project_files(codestreams, ffuncs, [utils.ARCH])

    with caplog.at_level(logging.WARNING):
        Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    assert "lib/seq_buf.o is not compiled with livepatch support (-pg flag)" in caplog.text
