# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2026 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

import logging
from pathlib import Path

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.utils import (filter_codestreams,
                                   filter_fast,
                                   get_cs_branch)
from klpbuild.klplib.kgraft import (create_release_branch,
                                    find_lp_branches,
                                    delete_lp_branches,
                                    make,
                                    get_kgraft,
                                    init_kgraft,
                                    reset_kgraft)

PLUGIN_CMD = "lint"

def register_argparser(subparser):
    fmt = subparser.add_parser(
        PLUGIN_CMD, help="Verify the code quality of the commited livepatches."
    )

    add_arg_lp_name(fmt)
    add_arg_lp_filter(fmt)
    fmt.add_argument("--gcc", type=int, default=0,
                     help="Use a specific gcc version (e.g 13, 15...)")


def gcc_report(log_file, lp_name):
    errors = 0
    warns = 0
    others = 0

    with open(log_file, "r", encoding="utf-8") as file:
        for l in file:
            if f"build/{lp_name}" in l:
                # Any errors related to the lp object
                if ": error:" in l:
                    errors += 1
                if ": warning:" in l:
                    warns += 1
            else:
                # Report any not related errors
                if ": error:" in l:
                    others += 1


    return errors, warns, others


def lint(lp_name, cs_list, gcc_version):
    init_kgraft()

    for cs in cs_list:
        lp_branch = get_cs_branch(cs, lp_name, get_kgraft())
        if not lp_branch:
            logging.info("%s: No branch found. Skipping.", cs.full_cs_name())
            continue

        logging.info("%s (%s):", cs.full_cs_name(), lp_branch)

        lint_branch = create_release_branch(cs, lp_branch, "lint")
        if not lint_branch:
            logging.info("Failed to create a release branch. Skipping.")
            continue

        prj_path = Path(cs.get_ccp_dir(lp_name), "build")
        gcc_log = Path(cs.get_ccp_dir(lp_name), "gcc.log")
        err = make(prj_path, cs, gcc_version, gcc_log)

        errors, warns, others = gcc_report(gcc_log, lp_name)

        logging.info(" %s (%d warnings, %d errors, %d others)",
                     "OK" if not err else "BAD",
                     warns, errors, others)

        if err:
            logging.info(" Saved in %s", gcc_log)

    br = find_lp_branches(f"lint*{lp_name}*")
    delete_lp_branches(br)

    reset_kgraft()


def run(lp_name, lp_filter, gcc):
    supported_codestreams = get_supported_codestreams()
    if lp_filter:
        filtered_codestreams = filter_codestreams(lp_filter, supported_codestreams)
    else:
        filtered_codestreams = filter_fast(lp_name, supported_codestreams)

    lint(lp_name, filtered_codestreams, gcc)
