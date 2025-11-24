# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import sys

from klpbuild.klplib import logger
from klpbuild.klplib.cmd import create_parser
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.klplib.plugins import try_run_plugin


def main():
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])

    logger.load_config()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if hasattr(args, 'lp_name'):
        load_codestreams(args.lp_name)

    if not args.cmd:
        print("Missing required command.")
        parser.print_help()
        sys.exit(1)

    try_run_plugin(args.cmd, args)


if __name__ == "__main__":
    main()
