# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

PLUGIN_CMD = "clean-sources"

def register_argparser(subparser):
    subparser.add_parser(
        PLUGIN_CMD, help="Clean extracted sources."
    )


def run():
    pass
