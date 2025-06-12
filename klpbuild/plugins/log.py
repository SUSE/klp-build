# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import sys

from osctiny import Osc

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.codestreams_data import get_codestreams_dict
from klpbuild.klplib.ibs import convert_cs_to_prj, prj_prefix
from klpbuild.klplib.utils import ARCHS, filter_codestreams

PLUGIN_CMD = "log"


def register_argparser(subparser):
    log_arg = subparser.add_parser(
        PLUGIN_CMD, help="Get build log from IBS"
    )

    add_arg_lp_name(log_arg)
    add_arg_lp_filter(log_arg)
    log_arg.add_argument("--arch", type=str, default="x86_64", choices=ARCHS, help="Build architecture")


def log(lp_name, lp_filter, arch):
    cs_list = filter_codestreams(lp_filter, get_codestreams_dict())

    if not cs_list:
        logging.error("log: No codestreams found for filter %s", lp_filter)
        sys.exit(1)

    if len(cs_list) > 1:
        cs_names = [cs.name() for cs in cs_list]
        logging.error("Filter '%s' returned %d entries (%s), while expecting just one. Aborting. ",
                      lp_filter, len(cs_list), " ".join(cs_names))
        sys.exit(1)

    osc = Osc(url="https://api.suse.de")
    prefix = prj_prefix(lp_name, osc)

    logging.info(osc.build.get_log(convert_cs_to_prj(cs_list[0], prefix), "standard", arch, "klp"))


def run(lp_name, lp_filter, arch):
    log(lp_name, lp_filter, arch)
