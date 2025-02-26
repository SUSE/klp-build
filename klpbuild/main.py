# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import sys

from klpbuild.klplib.cmd import create_parser
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.klplib.ibs import IBS
from klpbuild.klplib.ksrc import GitHelper
from klpbuild.klplib.utils import get_workdir
from klpbuild.klplib.plugins import try_run_plugin
from klpbuild.plugins.extractor import Extractor
from klpbuild.plugins.inline import Inliner
from klpbuild.plugins.setup import Setup


def main():
    args = create_parser().parse_args(sys.argv[1:])

    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format="%(message)s")

    if hasattr(args, 'name'):
        load_codestreams(args.name)

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
    if args.cmd == "setup":
        setup = Setup(args.name)
        ffuncs = Setup.setup_file_funcs(args.conf, args.module, args.file_funcs,
                                        args.mod_file_funcs, args.conf_mod_file_funcs)
        codestreams = setup.setup_codestreams(
            {"cve": args.cve, "conf": args.conf, "lp_filter": args.lp_filter,
                "no_check": args.no_check})
        setup.setup_project_files(codestreams, ffuncs, args.archs)

    elif args.cmd == "extract":
        Extractor(args.name, args.lp_filter, args.apply_patches, args.avoid_ext).run()

    elif args.cmd == "cs-diff":
        Extractor(args.name, args.lp_filter, False, []).cs_diff()

    elif args.cmd == "check-inline":
        Inliner(args.name, args.codestream).check_inline(args.file, args.symbol)

    elif args.cmd == "get-patches":
        GitHelper(args.lp_filter).get_commits(args.cve, get_workdir(args.name))

    elif args.cmd == "format-patches":
        GitHelper(args.lp_filter).format_patches(args.name, args.version)

    elif args.cmd == "status":
        IBS(args.name, args.lp_filter).status(args.wait)

    elif args.cmd == "push":
        IBS(args.name, args.lp_filter).push(args.wait)

    elif args.cmd == "log":
        IBS(args.name, args.lp_filter).log(args.arch)

    elif args.cmd == "cleanup":
        IBS(args.name, args.lp_filter).cleanup()

    elif args.cmd == "prepare-tests":
        IBS(args.name, args.lp_filter).prepare_tests()


if __name__ == "__main__":
    main()
