# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import sys

from klpbuild.klplib.cache import init_cache
from klpbuild.klplib.cmd import create_parser
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.klplib.config import get_user_settings
from klpbuild.klplib.plugins import try_run_plugin


def main():
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])

    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format="%(message)s")

    # TODO: implement get_user_settings_bool()
    cache_enabled = get_user_settings("cache", isopt=True) == "True" and (not args.nocache)
    init_cache(cache_enabled)

    if hasattr(args, 'lp_name'):
        load_codestreams(args.lp_name)

    if not args.cmd:
        print("Missing required command.")
        parser.print_help()
        exit(1)

    try_run_plugin(args.cmd, args)


if __name__ == "__main__":
    main()
