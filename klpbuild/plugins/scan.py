# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import sys

from klpbuild.klplib import utils
from klpbuild.klplib import patch
from klpbuild.klplib.ibs import IBS
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.data import download_missing_cs_data
from klpbuild.klplib.ksrc import get_commits, get_patched_kernels, cs_is_affected

PLUGIN_CMD = "scan"

def register_argparser(subparser):
    scan = subparser.add_parser(PLUGIN_CMD)
    scan.add_argument(
        "--cve",
        required=True,
        help="Shows which codestreams are vulnerable to the CVE"
    )
    scan.add_argument(
        "--conf",
        required=False,
        help="Helps to check only the codestreams that have this config set."
    )
    scan.add_argument(
        "--download",
        required=False,
        action="store_true",
        help="SLE specific. Download missing codestreams data"
    )


def run(cve, conf, lp_filter, no_check, download):
    no_check = False

    return scan(cve, conf, no_check, lp_filter, download)


def scan(cve, conf, no_check, lp_filter, download, savedir=None):
    # Always get the latest supported.csv file and check the content
    # against the codestreams informed by the user
    all_codestreams = get_supported_codestreams()

    # list of codestreams that matches the file-funcs argument
    working_cs = []
    patched_cs = []
    unaffected_cs = []
    conf_not_set = []
    unsupported = []

    if not cve or no_check:
        logging.info("Option --no-check was specified, checking all codestreams that are not filtered out...")
        working_cs = utils.filter_codestreams(lp_filter, all_codestreams)
        commits = {}
        patched_kernels = []
    else:
        commits = get_commits(cve, savedir)
        patched_kernels = get_patched_kernels(all_codestreams, commits, cve)

        for cs in utils.filter_codestreams(lp_filter, all_codestreams, verbose=True):

            if cs.kernel in patched_kernels:
                patched_cs.append(cs.name())
                continue

            if not cs_is_affected(cs, cve, commits):
                unaffected_cs.append(cs)
                continue

            working_cs.append(cs)

    # Download also if conf is set, because the codestreams data are needed to
    # check for the configuration entry of each codestreams.
    if conf or download:
        download_missing_cs_data(working_cs)

    # Automated patch analysis phase. Not compatible with --conf.
    if commits and not conf:
        logging.info("Initiating patch analysis...\n")
        logging.info("[*] Analysing modified files...\n")
        files_report = patch.analyse_files(working_cs, commits)
        patch.print_files(files_report)

        logging.info("[*] Analysing required CONFIGs...\n")
        configs_report = patch.analyse_configs(working_cs)
        patch.print_configs(configs_report)
        conf_not_set, conf = patch.filter_unset_configs(working_cs)

        logging.info("[*] Analysing affected kernel modules...\n")
        kmodules_report = patch.analyse_kmodules(working_cs)
        patch.print_kmodules(kmodules_report)
        unsupported = patch.filter_unsupported_kmodules(working_cs)

    # If conf is set, drop codestream not containing that conf entry from working_cs
    elif conf:
        tmp_working_cs = []
        for cs in working_cs:
            # TODO: here we could check for affected arch automatically
            if not cs.get_all_configs(conf):
                conf_not_set.append(cs)
            else:
                tmp_working_cs.append(cs)
        working_cs = tmp_working_cs

    if unsupported:
        logging.info(f"Skipping codestreams with unsupported kernel modules:")
        logging.info("\t%s", utils.classify_codestreams_str(unsupported))

    if conf_not_set:
        logging.info("Skipping codestreams without %s set:", conf)
        logging.info("\t%s", utils.classify_codestreams_str(conf_not_set))

    if patched_cs:
        logging.info("Skipping already patched codestreams:")
        logging.info("\t%s", utils.classify_codestreams_str(patched_cs))

    if unaffected_cs:
        logging.info("Skipping unaffected codestreams (missing backports):")
        logging.info("\t%s", utils.classify_codestreams_str(unaffected_cs))

    if not working_cs:
        logging.info("All supported codestreams are already patched. Exiting klp-build")
        sys.exit(0)

    logging.info("All affected codestreams:")
    logging.info("\t%s", utils.classify_codestreams_str(working_cs))

    return commits, patched_cs, patched_kernels, working_cs
