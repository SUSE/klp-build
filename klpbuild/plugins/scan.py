# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import re
import sys

from klpbuild.klplib import utils
from klpbuild.klplib.ibs import IBS
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.ksrc import GitHelper

PLUGIN_CMD = "scan"

def register_argparser(subparser):
    scan = subparser.add_parser(PLUGIN_CMD)
    scan.add_argument(
        "--cve",
        required=True,
        help="SLE specific. Shows which codestreams are vulnerable to the CVE"
    )
    scan.add_argument(
        "--conf",
        required=False,
        help="SLE specific. Helps to check only the codestreams that have this config set."
    )


def run(cve, conf, lp_filter, no_check):
    no_check = False

    return scan(cve, conf, no_check, lp_filter)


def scan(cve, conf, no_check, lp_filter, savedir=None):
    gh = GitHelper(lp_filter)
    # Always get the latest supported.csv file and check the content
    # against the codestreams informed by the user
    all_codestreams = get_supported_codestreams()

    if not cve or no_check:
        commits = {}
        patched_kernels = []
    else:
        commits = gh.get_commits(cve, savedir)
        patched_kernels = gh.get_patched_kernels(all_codestreams, commits, cve)

    # list of codestreams that matches the file-funcs argument
    working_cs = []
    patched_cs = []
    unaffected_cs = []
    data_missing = []
    cs_missing = []
    conf_not_set = []

    if no_check:
        logging.info("Option --no-check was specified, checking all codestreams that are not filtered out...")

    for cs in all_codestreams:

        # Skip filtered code streams
        if lp_filter and not re.match(lp_filter, cs.name()):
            logging.debug("	skipping code stream: %s", cs.name())
            continue

        # Skip patched codestreams
        if not no_check:
            if cs.kernel in patched_kernels:
                patched_cs.append(cs.name())
                continue

            if not GitHelper.cs_is_affected(cs, cve, commits):
                unaffected_cs.append(cs)
                continue

        if conf and not cs.get_boot_file("config").exists():
            data_missing.append(cs)
            cs_missing.append(cs.name())
            # recheck later if we can add the missing codestreams
            continue

        if conf and not cs.get_all_configs(conf):
            conf_not_set.append(cs)
            continue

        working_cs.append(cs)

    # Found missing cs data, downloading and extract
    if data_missing:
        logging.info("Download the necessary data from the following codestreams:")
        logging.info("\t%s\n", " ".join(cs_missing))
        IBS("", lp_filter).download_cs_data(data_missing)
        logging.info("Done.")

        for cs in data_missing:
            # Ok, the downloaded codestream has the configuration set
            if cs.get_all_configs(conf):
                working_cs.append(cs)
            # Nope, the config is missing, so don't add it to working_cs
            else:
                conf_not_set.append(cs)

    if conf_not_set:
        logging.info("Skipping codestreams without %s set:", conf)
        logging.info("\t%s", utils.classify_codestreams_str(conf_not_set))

    if patched_cs:
        logging.info("Skipping already patched codestreams:")
        logging.info("\t%s", utils.classify_codestreams_str(patched_cs))

    if unaffected_cs:
        logging.info("Skipping unaffected codestreams (missing backports):")
        logging.info("\t%s", utils.classify_codestreams_str(unaffected_cs))

    # working_cs will contain the final dict of codestreams that wast set
    # by the user, avoid downloading missing codestreams that are not affected
    working_cs = utils.filter_codestreams(lp_filter, working_cs, verbose=True)

    if not working_cs:
        logging.info("All supported codestreams are already patched. Exiting klp-build")
        sys.exit(0)

    logging.info("All affected codestreams:")
    logging.info("\t%s", utils.classify_codestreams_str(working_cs))

    return commits, patched_cs, patched_kernels, working_cs
