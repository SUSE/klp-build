# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import sys

from klpbuild.klplib.cmd import create_parser
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.klplib.plugins import try_run_plugin


def main():
    args = create_parser().parse_args(sys.argv[1:])

    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format="%(message)s")

    if hasattr(args, 'lp_name'):
        load_codestreams(args.lp_name)

    try_run_plugin(args.cmd, args)


if __name__ == "__main__":
    main()
