#!/usr/bin/env python3

import argparse

from ccp import CCP
from ksrc import GitHelper
from lp_setup import Setup
from ibs import IBS

def create_parser() -> argparse.ArgumentParser:
    archs = ['ppc64le', 's390x', 'x86_64']

    parentparser = argparse.ArgumentParser(add_help=False)
    parentparser.add_argument('-b', '--bsc', type=int, required=True,
            help='The bsc number related to this livepatch. This will be the directory name of the resulting livepatches')
    parentparser.add_argument('--filter', type=str,
            help='Filter out codestreams using a regex. Example: 15\.3u[0-9]+')

    parser = argparse.ArgumentParser(add_help=False)
    sub = parser.add_subparsers(dest='cmd')

    setup = sub.add_parser('setup', parents = [parentparser])
    setup.add_argument('--cve', type=str, required=True,
            help='The CVE assigned to this livepatch')
    setup.add_argument('--conf', type=str, default='',
            help='The kernel CONFIG used to be build the livepatch')
    setup.add_argument('--codestream', type=str, default='',
            help='Codestream of which the file and functions are related. Can '
                ' be used a regex, like, 15.u[34]')
    setup.add_argument('--file-funcs', required=False, action='append',
                       nargs='*', default=[],
            help='File and functions to be livepatched. Can be set '
            'multiple times. The format is --file-funcs file/path.c func1 '
            'func2 --file-func file/patch2 func1...')
    setup.add_argument('--mod-file-funcs', required=False, action='append',
                       nargs='*', default=[],
            help='Module, file and functions to be livepatched. Can be set '
            'multiple times. The format is --file-funcs module1 file/path.c func1 '
            'func2 --file-func module2 file/patch2 func1...')
    setup.add_argument('--conf-mod-file-funcs', required=False, action='append', nargs='*',
                       default=[],
            help='Conf, module, file and functions to be livepatched. Can be set '
            'multiple times. The format is --file-funcs conf1 module1 file/path.c func1 '
            'func2 --file-func conf2 module2 file/patch2 func1...')
    setup.add_argument('--module', type=str, default='vmlinux',
            help='The module that will be livepatched for all files')
    setup.add_argument('--archs', required=True, choices=archs, nargs='+',
                       help='Supported architectures for this livepatch')
    setup.add_argument('--skips', help='List of codestreams to filter out')

    ccp_opts = sub.add_parser('run-ccp', parents = [parentparser])
    ccp_opts.add_argument('--avoid-ext', nargs='+', type=str, default=[],
            help='Functions to be copied into the LP by klp-ccp instead of externalizing. '
                 'Useful to make sure to include symbols that are optimized in different architectures')

    format = sub.add_parser('format-patches', parents = [parentparser],
            help='Extract patches from kgraft-patches')
    format.add_argument('-v', '--version', type=int, required=True,
            help='Version to be added, like vX')

    patches = sub.add_parser('get-patches', parents = [parentparser])
    patches.add_argument('--cve', required=True,
            help='CVE number to search for related backported patches')

    cleanup = sub.add_parser('cleanup', parents = [parentparser],
                             help='Remove livepatch packages from IBS')

    ibs = sub.add_parser('ibs', parents = [parentparser],
            help='Manipulate livepatch packages in IBS')

    ibs.add_argument('--download', action='store_true',
            help='Download livepatch rpms')

    ibs.add_argument('--prepare-tests', action='store_true',
            help='Prepare a tarball with the rpms and tests')

    ibs.add_argument('--skip-download', action='store_true', default=False,
            help='Do not drop and redownload the built rpms')

    push = sub.add_parser('push', parents = [parentparser],
            help='Push livepatch packages to IBS to be built')
    push.add_argument('--wait', action='store_true',
            help='Wait until all codestreams builds are finished')

    status = sub.add_parser('status', parents = [parentparser],
            help='Check livepatch build status on IBS')
    status.add_argument('--wait', action='store_true',
            help='Wait until all codestreams builds are finished')

    log = sub.add_parser('log', parents = [parentparser],
            help='Get build log from IBS')
    log.add_argument('--cs', type=str, required=True,
            help='The codestream to get the log from')
    log.add_argument('--arch', type=str, default='x86_64', choices=archs,
                     help='Build architecture')

    return parser

def main_func(main_args):
    args = create_parser().parse_args(main_args)

    if args.cmd == 'setup':
        setup = Setup(args.bsc, args.filter, args.cve, args.codestream,
                      args.file_funcs, args.mod_file_funcs, args.conf_mod_file_funcs,
                      args.module, args.conf, args.archs, args.skips)
        setup.setup_project_files()

    elif args.cmd == 'run-ccp':
        CCP(args.bsc, args.filter, args.avoid_ext).run_ccp()

    elif args.cmd == 'get-patches':
        GitHelper(args.bsc, args.filter).get_commits(args.cve)

    elif args.cmd == 'format-patches':
        GitHelper(args.bsc, args.filter).format_patches(args.version)

    elif args.cmd == 'status':
        IBS(args.bsc, args.filter).status(args.wait)

    elif args.cmd == 'push':
        IBS(args.bsc, args.filter).push(args.wait)

    elif args.cmd == 'log':
        IBS(args.bsc, args.filter).log(args.cs, args.arch)

    elif args.cmd == 'cleanup':
        IBS(args.bsc, args.filter).cleanup()

    elif args.cmd == 'ibs':
        ibs = IBS(args.bsc, args.filter)
        if args.download:
            ibs.download()
        elif args.prepare_tests:
            ibs.prepare_tests(args.skip_download)
