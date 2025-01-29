# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import sys

from klpbuild.klplib import utils
from klpbuild.klplib.ibs import IBS
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.ksrc import GitHelper


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
        # Skip patched codestreams
        if not no_check:
            if cs.kernel in patched_kernels:
                patched_cs.append(cs.name())
                continue

            if not GitHelper.cs_is_affected(cs, cve, commits):
                unaffected_cs.append(cs)
                continue

        cs.set_archs()

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
        cs_list = utils.classify_codestreams(conf_not_set)
        logging.info("Skipping codestreams without %s set:", conf)
        logging.info("\t%s", " ".join(cs_list))

    if patched_cs:
        cs_list = utils.classify_codestreams(patched_cs)
        logging.info("Skipping already patched codestreams:")
        logging.info("\t%s", " ".join(cs_list))

    if unaffected_cs:
        cs_list = utils.classify_codestreams(unaffected_cs)
        logging.info("Skipping unaffected codestreams (missing backports):")
        logging.info("\t%s", " " .join(cs_list))

    # working_cs will contain the final dict of codestreams that wast set
    # by the user, avoid downloading missing codestreams that are not affected
    working_cs = utils.filter_codestreams(lp_filter, working_cs, verbose=True)

    if not working_cs:
        logging.info("All supported codestreams are already patched. Exiting klp-build")
        sys.exit(0)

    logging.info("All affected codestreams:")
    cs_list = utils.classify_codestreams(working_cs)
    logging.info("\t%s", " ".join(cs_list))

    return commits, patched_cs, patched_kernels, working_cs
