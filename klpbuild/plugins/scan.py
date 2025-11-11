# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import re
import sys
import concurrent.futures
import tabulate

from klpbuild.klplib import utils
from klpbuild.klplib import patch
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.data import download_missing_cs_data
from klpbuild.klplib.ksrc import get_patches
from klpbuild.klplib.bugzilla import get_pending_bugs, get_bug_data, is_bug_dropped, get_bug_dep

PLUGIN_CMD = "scan"

def register_argparser(subparser):
    scan = subparser.add_parser(PLUGIN_CMD)
    scan.add_argument(
        "--cve",
        required=False,
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

def run(cve, conf, lp_filter, download):
    if not cve:
        scan_bugzilla()
        return

    return scan(cve, conf, lp_filter, download)


def scan_bugzilla():
    table = []
    pool = {}

    bugs = get_pending_bugs()

    logging.info("Scanning %d bugs...", len(bugs))

    # Restrict logging to just errors
    logging.getLogger().setLevel(logging.ERROR)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for b in bugs:
            cve, system, cvss, level, prio  = get_bug_data(b)
            if not cve:
                continue
            job = executor.submit(scan_job, b, cve)
            pool[job] = [b.id, cve, system, cvss, level, prio]

        for job in concurrent.futures.as_completed(pool):
            bug = pool[job]
            bug.extend(job.result())
            table.append(bug)

    # Restore the original log level
    logging.getLogger().setLevel(logging.INFO)

    logging.info(tabulate.tabulate(table, headers=["ID", "CVE", "SUBSYSTEM", "CVSS", "PRIORITY",
                                                   "CLASSIFICATION", "STATUS", "AFFECTED"]))


def scan_job(bug, cve):
    affected = "No"
    status = "Not-Fixed"

    patches, _, _, affected_cs = scan(cve, None, None, False)

    # Check if parent bug has been discarded
    dep = get_bug_dep(bug)
    if is_bug_dropped(dep):
        status = "Dropped"

    npatches = len(set(f for _, files in patches.items() for f in files))
    if npatches:
        status = f"Fixed({npatches})"

    if dep and "security-team" not in dep.assigned_to:
        status = f"Incomplete({npatches})"

    if affected_cs:
        affected = utils.classify_codestreams_str(affected_cs)

    return status, affected


def scan(cve, conf, lp_filter, download, archs=utils.ARCHS, savedir=None):
    # Support CVEs from 2020 up to 2029
    assert cve and re.match(r"^202[0-9]-[0-9]{4,7}$", cve)

    upstream, patches = get_patches(cve, savedir)

    all_codestreams = get_supported_codestreams()
    filtered_codesteams = utils.filter_codestreams(lp_filter, all_codestreams, verbose=True)
    filtered_codesteams = utils.filter_codestreams_by_arch(archs, filtered_codesteams)

    affected_cs, unaffected_cs, patched_cs = filter_affected_codestreams(filtered_codesteams, patches)

    # Download also if conf is set, because the codestreams data are needed to
    # check for the configuration entry of each codestreams.
    if conf or download:
        download_missing_cs_data(affected_cs)

    # Automated patch analysis phase. Not compatible with --conf.
    conf_not_set = []
    unsupported = []
    if patches and not conf:
        logging.info("Initiating patch analysis...\n")
        logging.info("[*] Analysing modified files...\n")
        files_report = patch.analyse_files(affected_cs, patches)
        patch.print_files(files_report)

        logging.info("[*] Analysing required CONFIGs...\n")
        configs_report = patch.analyse_configs(affected_cs)
        patch.print_configs(configs_report)
        conf_not_set, conf = patch.filter_unset_configs(affected_cs)

        logging.info("[*] Analysing affected kernel modules...\n")
        kmodules_report = patch.analyse_kmodules(affected_cs)
        patch.print_kmodules(kmodules_report)
        unsupported = patch.filter_unsupported_kmodules(affected_cs)

        working_archs = utils.affected_archs(affected_cs)
        logging.info("Affected architectures:")
        logging.info("\t%s", ' '.join(working_archs))

    # If conf is set, drop codestream not containing that conf entry from working_cs
    elif conf:
        tmp_affected_cs = []
        for cs in affected_cs:
            if not cs.get_all_configs(conf):
                conf_not_set.append(cs)
            else:
                tmp_affected_cs.append(cs)
        affected_cs = tmp_affected_cs

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

    if not affected_cs:
        logging.info("All supported codestreams are already patched.")
    else:
        logging.info("All affected codestreams:")
        logging.info("\t%s\n", utils.classify_codestreams_str(affected_cs))

    return patches, upstream, patched_cs, affected_cs


def filter_affected_codestreams(codestreams, patches):
    # TODO: remove this
    if not patches:
        return []

    logging.info("Filtering already patched codestreams...")
    affected_codestreams = []   # Codestreams without all the patches
    unaffected_codestreams = [] # Codestreams belonging to a non affected product
    patched_codestreams = []    # Codestreams with all the patches

    for cs in codestreams:
        bc = cs.base_cs_name()
        suse_patches = patches[bc]

        if not suse_patches:
            unaffected_codestreams.append(cs)
            continue

        logging.debug("%s (%s) requires:", cs.full_cs_name(), cs.kernel)
        for patch in suse_patches:
            if not cs.has_patch(patch):
                # Store the patched required by this codestream for future use
                cs.add_required_patch(patch)
                logging.debug("\t%s", patch)
        logging.debug("")

        if cs.needs_patches():
            affected_codestreams.append(cs)
        else:
            patched_codestreams.append(cs)

    return affected_codestreams, unaffected_codestreams, patched_codestreams
