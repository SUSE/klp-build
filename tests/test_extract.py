# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import json
import inspect
import logging
import pytest

from klpbuild.plugins.extractor import Extractor
from klpbuild.plugins.setup import setup
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.klplib import utils

import tests.utils as tests_utils

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
        Extractor(lp_name=lp, apply_patches=False).run(lp_filter=cs, avoid_ext=[])

    assert "lib/seq_buf.o is not compiled with livepatch support (-pg flag)" in caplog.text


def test_compile_commands_enoent():
    """
    Check if the extraction fails when a file isn't found on
    compile_commands.json file
    """

    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.6u8"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": False,
        "archs": [utils.ARCH],
        "cve": None,
        "conf": "CONFIG_HID",
        "module": "vmlinux",
        "file_funcs": [["drivers/hid/hid-core.c", "hid_alloc_report_buf"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": []
    }
    setup(**setup_args)

    # rename the entry on files to a filename that doesn't exists (hid_core.c)
    data = tests_utils.get_codestreams_file(lp)
    file_funcs = data["codestreams"][cs]["files"].pop("drivers/hid/hid-core.c")
    data["codestreams"][cs]["files"]["drivers/hid/hid_core.c"] = file_funcs

    # write back the changed codestreams.json file
    with open(utils.get_workdir(lp)/"codestreams.json", "r+") as f:
        f.seek(0)
        f.write(json.dumps(data, indent=4))
        f.truncate()

    # reload the codestreams after the change
    load_codestreams(lp)

    # Now it should fail with hid_core.c that doesn't exists on compile_commands.json
    with pytest.raises(RuntimeError, match=r"Couldn't find cmdline for drivers/hid/hid_core.c on.*compile_commands.json. Aborting"):
        Extractor(lp_name=lp, apply_patches=False).run(lp_filter=cs, avoid_ext=[])


def test_detect_opt_clone(caplog):
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.3u47"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": False,
        "archs": [utils.ARCH],
        "cve": None,
        "conf": "CONFIG_BT",
        "module": "bluetooth",
        "file_funcs": [["net/bluetooth/l2cap_sock.c", "l2cap_sock_kill"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": []
    }
    setup(**setup_args)

    with caplog.at_level(logging.WARNING):
        Extractor(lp_name=lp, apply_patches=False).run(lp_filter=cs, avoid_ext=[])

    assert "Symbol l2cap_sock_kill contains optimized clone" in caplog.text
