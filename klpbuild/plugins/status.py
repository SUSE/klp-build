# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.ibs import status

PLUGIN_CMD = "status"


def register_argparser(subparser):
    st = subparser.add_parser(
        PLUGIN_CMD, help="Check livepatch build status on IBS."
    )

    add_arg_lp_name(st)
    add_arg_lp_filter(st)
    st.add_argument("--wait", action="store_true",
                    help="Wait unti all codestreams builds are finished")


def run(lp_name, lp_filter, wait=False):
    status(lp_name, lp_filter, wait)
