# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import concurrent.futures
import tabulate

from klpbuild.klplib import utils
from klpbuild.klplib import patch
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.data import download_missing_cs_data
from klpbuild.klplib.ksrc import get_patches, get_patched_kernels, cs_is_affected
from klpbuild.klplib.bugzilla import get_pending_bugs, get_bug_data, is_bug_dropped, get_bug_dep

PLUGIN_CMD = "scan"


def register_argparser(subparser):
    args = subparser.add_parser(PLUGIN_CMD)
    args.add_argument(
        "--cve",
        required=False,
        help="Shows which codestreams are vulnerable to the CVE"
    )
    args.add_argument(
        "--conf",
        required=False,
        help="Helps to check only the codestreams that have this config set."
    )
    args.add_argument(
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
            cve, system, cvss, prio  = get_bug_data(b)
            if not cve:
                continue
            job = executor.submit(scan_job, b, cve)
            pool[job] = [b.id, cve, system, cvss, prio]

        for job in concurrent.futures.as_completed(pool):
            bug = pool[job]
            bug.extend(job.result())
            table.append(bug)

    # Restore the original log level
    logging.getLogger().setLevel(logging.INFO)

    logging.info(tabulate.tabulate(table, headers=["ID", "CVE", "SUBSYSTEM", "CVSS", "PRIORITY",
                                                   "STATUS", "ARCHS", "AFFECTED"]))


def scan_job(bug, cve):
    affected = "No"
    status = "Not-Fixed"
    affected_archs = "None"

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

    # All = ppc64le, s390x and x86_64
    # None = klp-build failed to determine the CONFIGs.
    if (archs := utils.affected_archs(affected_cs)):
        affected_archs = "All" if archs == utils.ARCHS else ','.join(archs)

    return status, affected_archs, affected


def scan(cve, conf, lp_filter, download, archs=None, savedir=None):

    assert cve and utils.is_cve_valid(cve)

    if not archs:
        archs = utils.ARCHS

    upstream, patches = get_patches(cve, savedir)

    all_codestreams = get_supported_codestreams()
    filtered_codesteams = utils.filter_codestreams(lp_filter, all_codestreams, verbose=True)
    patched_kernels = get_patched_kernels(filtered_codesteams, patches)

    working_cs = []
    patched_cs = []
    unaffected_cs = []
    for cs in filtered_codesteams:

        # Skip codestreams that do not support the given archs.
        cs.set_archs(archs)
        if not cs.archs:
            continue

        if cs.kernel in patched_kernels:
            patched_cs.append(cs.full_cs_name())
            continue

        if not cs_is_affected(cs, cve, patches):
            unaffected_cs.append(cs)
            continue

        working_cs.append(cs)

    # Download also if conf is set, because the codestreams data are needed to
    # check for the configuration entry of each codestreams.
    if conf or download:
        download_missing_cs_data(working_cs)

    # Automated patch analysis phase. Not compatible with --conf.
    conf_not_set = []
    unsupported = []
    if patches and not conf:
        logging.info("Initiating patch analysis...\n")
        logging.info("[*] Analysing modified files...\n")
        files_report = patch.analyse_files(working_cs, patches)
        patch.print_files(files_report)

        logging.info("[*] Analysing required CONFIGs...\n")
        configs_report = patch.analyse_configs(working_cs)
        patch.print_configs(configs_report)
        conf_not_set, conf = patch.filter_unset_configs(working_cs)

        logging.info("[*] Analysing affected kernel modules...\n")
        kmodules_report = patch.analyse_kmodules(working_cs)
        patch.print_kmodules(kmodules_report)
        unsupported = patch.filter_unsupported_kmodules(working_cs)

        working_archs = utils.affected_archs(working_cs)
        logging.info("Affected architectures:")
        logging.info("\t%s", ' '.join(working_archs))
    # If conf is set, drop codestream not containing that conf entry from working_cs
    elif conf:
        tmp_working_cs = []
        for cs in working_cs:
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
        logging.info("All supported codestreams are already patched.")
    else:
        logging.info("All affected codestreams:")
        logging.info("\t%s\n", utils.classify_codestreams_str(working_cs))

    return patches, upstream, patched_cs, working_cs
