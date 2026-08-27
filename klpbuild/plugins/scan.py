# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import dataclasses
import logging
import concurrent.futures
import tabulate
from dataclasses import dataclass

from klpbuild.klplib import utils
from klpbuild.klplib.analysis import (
    analyse_files, analyse_kmodules, analyse_configs,
    print_files, print_kmodules, print_configs,
    filter_unsupported_kmodules,
    filter_unset_configs,
)
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.data import download_missing_cs_data
from klpbuild.klplib.ksrc import get_patches
from klpbuild.klplib.bugzilla import (
        get_pending_bugs, get_bug_data,
        is_bug_dropped, get_bug_dep,
        is_bug_embargoed,
        is_bug_fixed)

@dataclass
class JobResult:
    status: str = "Not-Fixed"
    archs: str = "None"
    eol: str = "n/a"
    affected: str = "No"

    def __iter__(self):
        return dataclasses.astuple(self).__iter__()


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

    scan(cve, conf, lp_filter, download)


def scan_bugzilla():
    table = []
    pool = {}

    bugs = get_pending_bugs()

    logging.info("Scanning %d bugs...", len(bugs))

    # Restrict logging to just errors
    logging.getLogger().setLevel(logging.ERROR)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for b in bugs:
            if is_bug_embargoed(b):
                continue
            data = get_bug_data(b)
            if not data.cve:
                table.append([b.id, *data._replace(cve="None"), *JobResult()])
                continue
            job = executor.submit(scan_job, b, data.cve)
            pool[job] = [b.id, *data]

        for job in concurrent.futures.as_completed(pool):
            bug = pool[job]
            bug.extend(job.result())
            table.append(bug)

    # Restore the original log level
    logging.getLogger().setLevel(logging.INFO)

    logging.info(tabulate.tabulate(table, headers=["ID", "CVE", "SUBSYSTEM", "CVSS", "PRIORITY",
                                                   "DEADLINE", "STATUS", "ARCHS", "EOL", "AFFECTED"]))


def scan_job(bug, cve):
    result = JobResult()

    dep = get_bug_dep(bug)
    if not dep:
        result.status = "No-parent"
        return result

    if is_bug_dropped(dep):
        result.status = "Dropped"
        return result

    if is_bug_fixed(dep):
        result.status = "Fixed(0)"

    patches, _, _, affected_cs = scan(cve, None, None, False)

    npatches = len(set(f for _, files in patches.items() for f in files))
    if npatches:
        result.status = f"Fixed({npatches})"

    if dep and "security-team" not in dep.assigned_to:
        result.status = f"Incomplete({npatches})"

    if affected_cs:
        result.affected = utils.classify_codestreams_str(affected_cs)
        result.eol = utils.get_lp_eol(affected_cs)

    # All = ppc64le, s390x and x86_64
    # None = klp-build failed to determine the CONFIGs.
    if (archs := utils.affected_archs(affected_cs)):
        result.archs = "All" if set(archs) == utils.ARCHS else ','.join(archs)

    return result


def scan(cve, conf, lp_filter, download, archs=None, savedir=None, extra_patches=None):
    if archs is None:
        archs = utils.ARCHS
    if extra_patches is None:
        extra_patches = []

    assert cve and utils.is_cve_valid(cve)

    upstream, patches = get_patches(cve, savedir, extra_patches)

    all_codestreams = get_supported_codestreams()
    filtered_codesteams = utils.filter_codestreams(lp_filter, all_codestreams, verbose=True)
    filtered_codesteams = utils.filter_codestreams_by_arch(archs, filtered_codesteams)

    affected_cs, unaffected_cs, patched_cs = filter_affected_codestreams(filtered_codesteams, patches)

    # FIXME: the following statemend is no longer true since the config is
    # retrieved from the kernel-source:
    #
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
        files_report = analyse_files(affected_cs)
        print_files(files_report)

        logging.info("[*] Analysing required CONFIGs...\n")
        configs_report = analyse_configs(affected_cs)
        print_configs(configs_report)
        conf_not_set, conf = filter_unset_configs(affected_cs)

        logging.info("[*] Analysing affected kernel modules...\n")
        kmodules_report = analyse_kmodules(affected_cs)
        print_kmodules(kmodules_report)
        unsupported = filter_unsupported_kmodules(affected_cs)

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
        logging.info("Skipping codestreams with unsupported kernel modules:")
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
        if utils.is_lp_eol_soon(affected_cs):
            logging.warning("The livepatch EOL will be soon (%s).\n",
                            utils.get_lp_eol(affected_cs))

    return patches, upstream, patched_cs, affected_cs


def filter_affected_codestreams(codestreams, patches):
    logging.info("Filtering already patched codestreams...")
    affected_codestreams = []   # Codestreams without all the patches
    unaffected_codestreams = [] # Codestreams belonging to a non affected product
    patched_codestreams = []    # Codestreams with all the patches

    for cs in codestreams:
        suse_patches = patches[cs.base_cs_name()]

        if not suse_patches:
            unaffected_codestreams.append(cs)
            continue

        logging.debug("%s (%s) requires:", cs.full_cs_name(), cs.kernel)
        for suse_patch in suse_patches:
            if not cs.has_patch(suse_patch):
                # Store the patches required by this codestreams for future use
                cs.add_required_patch(suse_patch)
                logging.debug("\t%s", suse_patch)
        logging.debug("")

        if cs.needs_patches():
            affected_codestreams.append(cs)
        else:
            patched_codestreams.append(cs)

    return affected_codestreams, unaffected_codestreams, patched_codestreams
