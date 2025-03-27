# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import logging

from klpbuild.klplib.cmd import add_arg_lp_filter
from klpbuild.klplib.data import download_missing_cs_data, download_cs_data
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.utils import filter_codestreams

PLUGIN_CMD = "data"

def register_argparser(subparser):
    fmt = subparser.add_parser(
        PLUGIN_CMD, help="Manage codestreams data."
    )

    add_arg_lp_filter(fmt)
    fmt.add_argument("--download", required=True, action="store_true",
                     help="Download all the missing supported codestreams data")
    fmt.add_argument("--force",action="store_true",
                     help="Re-download also codestream that are not missing")


def run(download, force, lp_filter):
    supported_codestreams =  get_supported_codestreams()
    filtered_codestreams = filter_codestreams(lp_filter, supported_codestreams)

    if download:
        if force:
            download_cs_data(filtered_codestreams)
        else:
            download_missing_cs_data(filtered_codestreams)
    else:
        logging.error("Use --download")
