# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging

from osctiny import Osc

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.ibs import delete_projects, get_project_names

PLUGIN_CMD = "cleanup"


def register_argparser(subparser):
    clp = subparser.add_parser(
        PLUGIN_CMD, help="Remove livepatch packages from IBS"
    )

    add_arg_lp_name(clp)
    add_arg_lp_filter(clp)


def cleanup(lp_name, lp_filter):
    osc = Osc(url="https://api.suse.de")
    prjs = get_project_names(osc, lp_name, lp_filter)

    total = len(prjs)
    if total == 0:
        logging.info("No projects found.")
        return

    logging.info("Deleting %d projects...", total)

    delete_projects(osc, prjs, True)


def run(lp_name, lp_filter):
    cleanup(lp_name, lp_filter)
