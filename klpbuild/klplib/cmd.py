# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import argparse
import importlib.metadata

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

    parentparser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s v{importlib.metadata.version('klp-build')}"
    )

    register_plugins_argparser(sub)

    # NOTE: all the code below should be gone when all the module will be
    # converted into plugins
    extract_opts = sub.add_parser("extract", help="Extract initial livepatches")
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
        "--apply-patches", action="store_true", help="Apply patches if they exist"
    )

    diff_opts = sub.add_parser(
            "cs-diff",
            help="Compare line by line the output livepatch of two codestreams")
    add_arg_lp_name(diff_opts)
    add_arg_lp_filter(diff_opts)

    cleanup =sub.add_parser("cleanup", help="Remove livepatch packages from IBS")
    add_arg_lp_name(cleanup)
    add_arg_lp_filter(cleanup)

    return parentparser
