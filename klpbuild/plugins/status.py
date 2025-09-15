# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import time

from osctiny import Osc

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.ibs import get_project_names

PLUGIN_CMD = "status"


def register_argparser(subparser):
    st = subparser.add_parser(
        PLUGIN_CMD, help="Check livepatch build status on IBS."
    )

    add_arg_lp_name(st)
    add_arg_lp_filter(st)
    st.add_argument("--wait", action="store_true",
                    help="Wait unti all codestreams builds are finished")


def status(lp_name, lp_filter, wait=False):
    finished_prj = []

    osc = Osc(url="https://api.suse.de")

    while True:
        prjs = {}
        for _, prj in get_project_names(osc, lp_name, lp_filter):
            if prj in finished_prj:
                continue

            prjs[prj] = {}

            for res in osc.build.get(prj).findall("result"):
                if not res.xpath("status/@code"):
                    continue
                code = res.xpath("status/@code")[0]
                prjs[prj][res.get("arch")] = code

        logging.info("%d codestreams to finish", len(prjs))

        for prj, archs in prjs.items():
            st = []
            finished = False
            # Save the status of all architecture build, and set to fail if
            # an error happens in any of the supported architectures
            for k, v in archs.items():
                st.append(f"{k}: {v}")
                if v in ["unresolvable", "failed"]:
                    finished = True

            # Only set finished is all architectures supported by the
            # codestreams built without issues
            if not finished:
                states = set(archs.values())
                if len(states) == 1 and states.pop() in ["succeeded", "excluded"]:
                    finished = True

            if finished:
                finished_prj.append(prj)

            logging.info("%s\t%s", prj, "\t".join(st))

        for p in finished_prj:
            prjs.pop(p, None)

        if not wait or not prjs:
            break

        # Wait 30 seconds before getting status again
        time.sleep(30)
        logging.info("")


def run(lp_name, lp_filter, wait=False):
    status(lp_name, lp_filter, wait)
