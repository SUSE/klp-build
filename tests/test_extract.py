# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from klpbuild.extractor import Extractor
from klpbuild.setup import Setup
import klpbuild.utils as utils

import inspect
import logging

def test_detect_file_without_ftrace_support(caplog):
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.6u0"

    Setup(lp_name=lp, lp_filter=cs, cve=None, conf="CONFIG_SMP",
          file_funcs=[["lib/seq_buf.c", "seq_buf_putmem_hex"]],
          mod_file_funcs=[], conf_mod_file_funcs=[], mod_arg="vmlinux",
          archs=[utils.ARCH], skips=None, no_check=False).setup_project_files()

    with caplog.at_level(logging.WARNING):
        Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    assert "lib/seq_buf.o is not compiled with livepatch support (-pg flag)" in caplog.text
