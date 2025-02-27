# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import argparse

from klpbuild.klplib.utils import ARCHS
from klpbuild.klplib.plugins import register_plugins_argparser

def add_arg_lp_name(parentparser, mandatory=True):
    parentparser.add_argument(
        "-n",
        "--name",
        type=str,
        required=mandatory,
        dest="lp_name",
        help="The livepatch name. This will be the directory name of the "
        "resulting livepatches.",
    )


def add_arg_lp_filter(parentparser, mandatory=False):
    parentparser.add_argument(
        "--filter",
        type=str,
        required=mandatory,
        dest="lp_filter",
        help=r"Filter out codestreams using a regex. Example: 15\.3u[0-9]+"
    )


def create_parser() -> argparse.ArgumentParser:
    parentparser = argparse.ArgumentParser(add_help=True)
    sub = parentparser.add_subparsers(dest="cmd")

    parentparser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Produce more verbose output"
    )

    register_plugins_argparser(sub)

    # NOTE: all the code below should be gone when all the module will be
    # converted into plugins
    check_inline = sub.add_parser("check-inline")
    add_arg_lp_name(check_inline)
    add_arg_lp_filter(check_inline)
    check_inline.add_argument(
        "--codestream",
        type=str,
        default="",
        required=True,
        help="SLE specific. Codestream to check the inlined symbol.",
    )
    check_inline.add_argument(
        "--file",
        type=str,
        required=True,
        help="File to be checked.",
    )
    check_inline.add_argument(
        "--symbol",
        type=str,
        required=True,
        help="Symbol to be found",
    )

    extract_opts = sub.add_parser("extract")
    add_arg_lp_name(extract_opts)
    add_arg_lp_filter(extract_opts)
    extract_opts.add_argument(
        "--avoid-ext",
        nargs="+",
        type=str,
        default=[],
        help="Functions to be copied into the LP instead of externalizing. "
        "Useful to make sure to include symbols that are optimized in "
        "different architectures",
    )
    extract_opts.add_argument(
        "--apply-patches", action="store_true", help="Apply patches found by get-patches subcommand, if they exist"
    )

    diff_opts = sub.add_parser("cs-diff")
    add_arg_lp_name(diff_opts)
    add_arg_lp_filter(diff_opts)


    patches = sub.add_parser("get-patches")
    add_arg_lp_name(patches)
    add_arg_lp_filter(patches)
    patches.add_argument(
        "--cve", required=True, help="SLE specific. CVE number to search for related backported patches"
    )


    cleanup =sub.add_parser("cleanup", help="SLE specific. Remove livepatch packages from IBS")
    add_arg_lp_name(cleanup)
    add_arg_lp_filter(cleanup)

    test = sub.add_parser(
        "prepare-tests",
        help="SLE specific. Download the built tests and check for LP dependencies",
    )
    add_arg_lp_name(test)
    add_arg_lp_filter(test)

    push = sub.add_parser(
        "push", help="SLE specific. Push livepatch packages to IBS to be built"
    )
    add_arg_lp_name(push)
    add_arg_lp_filter(push)
    push.add_argument("--wait", action="store_true", help="Wait until all codestreams builds are finished")

    status = sub.add_parser("status", help="SLE specific. Check livepatch build status on IBS")
    add_arg_lp_name(status)
    add_arg_lp_filter(status)
    status.add_argument("--wait", action="store_true", help="Wait until all codestreams builds are finished")

    log = sub.add_parser("log", help="SLE specific. Get build log from IBS")
    add_arg_lp_name(log)
    add_arg_lp_filter(log, mandatory=True)
    log.add_argument("--arch", type=str, default="x86_64", choices=ARCHS, help="Build architecture")

    return parentparser
