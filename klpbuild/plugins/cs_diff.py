# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import difflib as dl
import logging
import sys

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.codestreams_data import get_codestreams_dict
from klpbuild.klplib.utils import filter_codestreams
from klpbuild.plugins.extract import get_cs_code

PLUGIN_CMD = "cs-diff"


def register_argparser(subparser):
    diff_opts = subparser.add_parser(
        PLUGIN_CMD, help="Compare line by line the output livepatch of two codestreams"
    )

    add_arg_lp_name(diff_opts)
    add_arg_lp_filter(diff_opts)


def cs_diff(lp_name, lp_filter):
    """
    To compare two codestreams the filter should result in exactly two codestreams
    """
    cs_args = filter_codestreams(lp_filter, get_codestreams_dict(), verbose=True)
    if len(cs_args) != 2:
        logging.error("The filter specified found %d while it should point to only 2.", len(cs_args))
        sys.exit(1)

    assert len(cs_args) == 2

    cs_code = get_cs_code(lp_name, cs_args)

    cs1 = cs_args[0].name()
    cs2 = cs_args[1].name()

    f1 = cs_code.get(cs1)
    f2 = cs_code.get(cs2)

    assert len(f1) == len(f2)

    for _, (v1, v2) in enumerate(zip(f1, f2)):
        for line in dl.unified_diff(v1[1].splitlines(), v2[1].splitlines(), fromfile=f"{cs1} {v1[0]}",
                                    tofile=f"{cs2} {v1[0]}"):
            logging.info(line)


def run(lp_name, lp_filter):
    cs_diff(lp_name, lp_filter)
