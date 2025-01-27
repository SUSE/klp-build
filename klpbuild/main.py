# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import sys

from klpbuild.klplib.cmd import create_parser
from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.klplib.ibs import IBS
from klpbuild.klplib.ksrc import GitHelper
from klpbuild.plugins.extractor import Extractor
from klpbuild.plugins.inline import Inliner
from klpbuild.plugins.setup import Setup


def main():
    args = create_parser().parse_args(sys.argv[1:])

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # NOTE: Here I'm assuming the codestream is only loaded for plugins that
    # get the livepatch name, not sure yet it's ok to assume it
    if hasattr(args, 'name'):
        load_codestreams(args.name)
    else:
        load_codestreams('bsc_check')

    if args.cmd == "setup":
        setup = Setup(args.name)
        ffuncs = Setup.setup_file_funcs(args.conf, args.module, args.file_funcs,
                                        args.mod_file_funcs, args.conf_mod_file_funcs)
        codestreams = setup.setup_codestreams(
            {"cve": args.cve, "conf": args.conf, "lp_filter": args.filter,
                "lp_skips": args.skips, "no_check": args.no_check})
        setup.setup_project_files(codestreams, ffuncs, args.archs)

    elif args.cmd == "extract":
        Extractor(args.name, args.filter, args.apply_patches, args.avoid_ext).run()

    elif args.cmd == "cs-diff":
        lp_filter = args.cs[0] + "|" + args.cs[1]
        Extractor(args.name, lp_filter, False, []).diff_cs()

    elif args.cmd == "check-inline":
        Inliner(args.name, args.codestream).check_inline(args.file, args.symbol)

    elif args.cmd == "get-patches":
        GitHelper(args.name, args.filter, "").get_commits(args.cve)

    elif args.cmd == "scan":
        GitHelper("bsc_check", "", "").scan(args.cve, args.conf, False)

    elif args.cmd == "format-patches":
        GitHelper(args.name, args.filter, "").format_patches(args.version)

    elif args.cmd == "status":
        IBS(args.name, args.filter).status(args.wait)

    elif args.cmd == "push":
        IBS(args.name, args.filter).push(args.wait)

    elif args.cmd == "log":
        IBS(args.name, args.filter).log(Codestream.from_cs(args.cs), args.arch)

    elif args.cmd == "cleanup":
        IBS(args.name, args.filter).cleanup()

    elif args.cmd == "prepare-tests":
        IBS(args.name, args.filter).prepare_tests()


if __name__ == "__main__":
    main()
