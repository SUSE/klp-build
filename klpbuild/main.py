# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import sys

from klpbuild.klplib.cmd import create_parser
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.klplib.ibs import IBS
from klpbuild.klplib.plugins import try_run_plugin
from klpbuild.plugins.extractor import Extractor


def main():
    args = create_parser().parse_args(sys.argv[1:])

    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format="%(message)s")

    if hasattr(args, 'lp_name'):
        load_codestreams(args.lp_name)

    try:
        try_run_plugin(args.cmd, args)
        return
    except (AssertionError, ModuleNotFoundError) as e:
        # TODO: this should be removed as soon as all the modules are converted
        # into plugins
        if isinstance(e, AssertionError) and not "is not a plugin!" in str(e):
                raise

        logging.debug("Plugin %s cannot be loaded dinamically!", args.cmd)

    # NOTE: all the code below should be gone when all the modules will be
    # converted into plugins
    if args.cmd == "extract":
        Extractor(args.lp_name, args.lp_filter, args.apply_patches, args.avoid_ext).run()

    elif args.cmd == "cs-diff":
        Extractor(args.lp_name, args.lp_filter, False, []).cs_diff()

    elif args.cmd == "status":
        IBS().status(args.lp_name, args.lp_filter, args.wait)

    elif args.cmd == "push":
        IBS().push(args.lp_name, args.lp_filter, args.wait)

    elif args.cmd == "log":
        IBS().log(args.lp_name, args.lp_filter, args.arch)

    elif args.cmd == "cleanup":
        IBS().cleanup(args.lp_name, args.lp_filter)

    elif args.cmd == "prepare-tests":
        IBS().prepare_tests(args.lp_name, args.lp_filter)


if __name__ == "__main__":
    main()
