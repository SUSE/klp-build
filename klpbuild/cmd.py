# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import argparse

from klpbuild.extractor import Extractor
from klpbuild.ibs import IBS
from klpbuild.inline import Inliner
from klpbuild.ksrc import GitHelper
from klpbuild.setup import Setup
from klpbuild.utils import ARCHS


def create_parser() -> argparse.ArgumentParser:
    parentparser = argparse.ArgumentParser(add_help=False)
    parentparser.add_argument(
        "-n",
        "--name",
        type=str,
        required=True,
        help="The livepatch name. This will be the directory name of the "
        "resulting livepatches.",
    )
    parentparser.add_argument("--filter", type=str, help=r"Filter out codestreams using a regex. Example: 15\.3u[0-9]+")
    parentparser.add_argument(
        "--experimental", action="store_true", help="Enables functions that may not work as expected yet."
    )

    parser = argparse.ArgumentParser(add_help=False)
    sub = parser.add_subparsers(dest="cmd")

    setup = sub.add_parser("setup", parents=[parentparser])
    setup.add_argument("--cve", type=str, help="SLE specific. The CVE assigned to this livepatch")
    setup.add_argument("--conf", type=str, required=True, help="The kernel CONFIG used to be build the livepatch")
    setup.add_argument(
        "--no-check",
        action="store_true",
        help="SLE specific. Do not check for already patched codestreams, do the setup for all non filtered codestreams.",
    )
    setup.add_argument(
        "--data-dir",
        type=str,
        required=False,
        default=None,
        help="The path where source files and modules will be found",
    )
    setup.add_argument(
        "--codestreams",
        type=str,
        default="",
        help="SLE specific. Codestreams affected by the CVE. Can be used a regex, like, 15.u[34]",
    )
    setup.add_argument(
        "--file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="File and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs file/path.c func1 "
        "func2 --file-func file/patch2 func1...",
    )
    setup.add_argument(
        "--mod-file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="Module, file and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs module1 file/path.c func1 "
        "func2 --file-func module2 file/patch2 func1...",
    )
    setup.add_argument(
        "--conf-mod-file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="Conf, module, file and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs conf1 module1 file/path.c func1 "
        "func2 --file-func conf2 module2 file/patch2 func1...",
    )
    setup.add_argument(
        "--module", type=str, default="vmlinux", help="The module that will be livepatched for all files"
    )
    setup.add_argument(
        "--archs",
        default=ARCHS,
        choices=ARCHS,
        nargs="+",
        help="SLE specific. Supported architectures for this livepatch",
    )
    setup.add_argument("--skips", help="List of codestreams to filter out")

    check_inline = sub.add_parser("check-inline", parents=[parentparser])
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

    extract_opts = sub.add_parser("extract", parents=[parentparser])
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
    extract_opts.add_argument(
        "--type", type=str, choices=["ccp", "ce"], default="ccp", help="Choose between ccp and ce"
    )
    extract_opts.add_argument("--workers", type=int, default=4, help="Number of processes for ccp and ce. Default is 4")

    diff_opts = sub.add_parser("cs-diff", parents=[parentparser])
    diff_opts.add_argument(
        "--codestreams", nargs=2, type=str, required=True, help="SLE specific. Apply diff on two different codestreams"
    )
    diff_opts.add_argument("--type", type=str, choices=["ccp", "ce"], default="ccp", help="Choose between ccp and ce")

    fmt = sub.add_parser(
        "format-patches", parents=[parentparser], help="SLE specific. Extract patches from kgraft-patches"
    )
    fmt.add_argument("-v", "--version", type=int, required=True, help="Version to be added, like vX")

    patches = sub.add_parser("get-patches", parents=[parentparser])
    patches.add_argument(
        "--cve", required=True, help="SLE specific. CVE number to search for related backported patches"
    )

    sub.add_parser("cleanup", parents=[parentparser], help="SLE specific. Remove livepatch packages from IBS")

    sub.add_parser(
        "prepare-tests",
        parents=[parentparser],
        help="SLE specific. Download the built tests and check for LP dependencies",
    )

    push = sub.add_parser(
        "push", parents=[parentparser], help="SLE specific. Push livepatch packages to IBS to be built"
    )
    push.add_argument("--wait", action="store_true", help="Wait until all codestreams builds are finished")

    status = sub.add_parser("status", parents=[parentparser], help="SLE specific. Check livepatch build status on IBS")
    status.add_argument("--wait", action="store_true", help="Wait until all codestreams builds are finished")

    log = sub.add_parser("log", parents=[parentparser], help="SLE specific. Get build log from IBS")
    log.add_argument("--cs", type=str, required=True, help="The codestream to get the log from")
    log.add_argument("--arch", type=str, default="x86_64", choices=ARCHS, help="Build architecture")

    return parser


def main_func(main_args):
    args = create_parser().parse_args(main_args)

    if args.cmd == "setup":
        setup = Setup(
            args.name,
            args.filter,
            args.data_dir,
            args.cve,
            args.codestreams,
            args.file_funcs,
            args.mod_file_funcs,
            args.conf_mod_file_funcs,
            args.module,
            args.conf,
            args.archs,
            args.skips,
            args.no_check,
        )
        setup.setup_project_files()

    elif args.cmd == "extract":
        Extractor(args.name, args.filter, args.apply_patches, args.type, args.avoid_ext, args.workers).run()

    elif args.cmd == "cs-diff":
        Extractor(args.name, "", False, args.type, []).diff_cs(args.codestreams)

    elif args.cmd == "check-inline":
        Inliner(args.name).check_inline(args.codestream, args.file, args.symbol)

    elif args.cmd == "get-patches":
        GitHelper(args.name, args.filter, False, None).get_commits(args.cve)

    elif args.cmd == "format-patches":
        GitHelper(args.name, args.filter, False, None).format_patches(args.version)

    elif args.cmd == "status":
        IBS(args.name, args.filter).status(args.wait)

    elif args.cmd == "push":
        IBS(args.name, args.filter).push(args.wait)

    elif args.cmd == "log":
        IBS(args.name, args.filter).log(args.cs, args.arch)

    elif args.cmd == "cleanup":
        IBS(args.name, args.filter).cleanup()

    elif args.cmd == "prepare-tests":
        IBS(args.name, args.filter).prepare_tests()
