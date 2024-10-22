# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from klpbuild.extractor import Extractor
from klpbuild.setup import Setup
import klpbuild.utils as utils

import logging

def test_detect_file_without_ftrace_support(caplog):
    lp = "bsc9999999"
    cs = "15.6u0"

    Setup(lp_name=lp, lp_filter=cs, data_dir=None, cve=None, cs_arg="",
          file_funcs=[["lib/seq_buf.c", "seq_buf_putmem_hex"]],
          mod_file_funcs=[], conf_mod_file_funcs=[], mod_arg="vmlinux",
          conf="CONFIG_SMP",
          archs=[utils.ARCH], skips=None, no_check=False).setup_project_files()

    with caplog.at_level(logging.WARNING):
        Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, app="ce",
                         avoid_ext=[], ignore_errors=False).run()

    assert "lib/seq_buf.o is not compiled with livepatch support (-pg flag)" in caplog.text
