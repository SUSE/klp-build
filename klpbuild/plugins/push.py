# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from osctiny import Osc

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.codestreams_data import get_codestreams_dict
from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.ibs import convert_cs_to_prj, delete_project, prj_prefix
from klpbuild.klplib.utils import classify_codestreams_str, filter_codestreams, get_cs_branch, get_kgraft_branch
from klpbuild.plugins.status import status

PLUGIN_CMD = "push"


def register_argparser(subparser):
    push_arg = subparser.add_parser(
        PLUGIN_CMD, help="Push livepatch packages to IBS to be built."
    )

    add_arg_lp_name(push_arg)
    add_arg_lp_filter(push_arg)
    push_arg.add_argument("--wait", action="store_true",
                          help="Wait unti all codestreams builds are finished")


def create_prj_meta(cs):
    return "<project name=''><title></title><description></description>" + \
               "<build><enable/></build>" + \
               "<publish><disable/></publish>" + \
               "<debuginfo><disable/></debuginfo>" + \
               "<repository name=\"standard\">" + \
               f"<path project=\"{cs.project}\" repository=\"{cs.get_repo()}\"/>" + \
               "".join([f"<arch>{arch}</arch>" for arch in cs.archs]) + \
               "</repository>" + \
           "</project>"


def create_lp_package(osc, lp_name, i, total, cs):
    kgr_path = get_user_path('kgr_patches_dir')
    branch = get_cs_branch(cs, lp_name, kgr_path)
    if not branch:
        logging.info("Could not find git branch for %s. Skipping.", cs.full_cs_name())
        return

    # If the project exists, drop it first
    prj = convert_cs_to_prj(cs, prj_prefix(lp_name, osc))
    delete_project(osc, 0, 0, prj, verbose=False)

    meta = create_prj_meta(cs)
    prj_desc = f"Development of livepatches for {cs.full_cs_name()}"

    try:
        osc.projects.set_meta(
            prj, metafile=meta, title="", bugowner=osc.username, maintainer=osc.username, description=prj_desc
        )

        osc.packages.set_meta(prj, "klp", title="", description="Test livepatch")

    except Exception as e:
        logging.error(e, str(e))
        raise RuntimeError("") from e

    # Remove previously created directories
    prj_path = Path(cs.get_ccp_dir(lp_name), "checkout")
    if prj_path.exists():
        shutil.rmtree(prj_path)

    code_path = Path(cs.get_ccp_dir(lp_name), "code")
    if code_path.exists():
        shutil.rmtree(code_path)

    osc.packages.checkout(prj, "klp", prj_path)

    base_branch = get_kgraft_branch(cs.full_cs_name())

    logging.info("(%s/%s) pushing %s using branches %s/%s...",
                 i, total, cs.full_cs_name(), str(base_branch), str(branch))

    # Clone the repo and checkout to the codestream branch. The branch should be based on master to avoid rebasing
    # conflicts
    subprocess.check_output(
        ["/usr/bin/git", "clone", "--branch", branch, str(kgr_path), str(code_path)],
        stderr=subprocess.STDOUT,
    )

    # Add remote with all codestreams, because the clone above will set the remote origin
    # to the local directory, so it can't find the remote codestreams
    subprocess.check_output(["/usr/bin/git", "remote", "add", "kgr",
                            "gitlab@gitlab.suse.de:kernel/kgraft-patches.git"],
                            stderr=subprocess.STDOUT, cwd=code_path)

    # Fetch all remote codestreams so we can rebase in the next step
    subprocess.check_output(["/usr/bin/git", "fetch", "kgr",  str(base_branch)],
                            stderr=subprocess.STDOUT, cwd=code_path)

    # Get the new bsc commit on top of the codestream branch (should be the last commit on the specific branch)
    subprocess.check_output(
        ["/usr/bin/git", "rebase", f"kgr/{base_branch}"],
        stderr=subprocess.STDOUT, cwd=code_path
    )

    # Check if the directory related to this bsc exists.
    # Otherwise only warn the caller about this fact.
    # This scenario can occur in case of LPing function that is already
    # part of different LP in which case we modify the existing one.
    if lp_name not in os.listdir(code_path):
        logging.warning("Warning: Directory %s not found on branch %s", lp_name, branch)

    # Fix RELEASE version
    with open(Path(code_path, "scripts", "release-version.sh"), "w") as f:
        ver = cs.get_full_product_name().replace("EMBARGO", "")
        f.write(f"RELEASE={ver}")

    subprocess.check_output(
        ["bash", "./scripts/tar-up.sh", "-d", str(prj_path)], stderr=subprocess.STDOUT, cwd=code_path
    )
    shutil.rmtree(code_path)

    # Add all files to the project, commit the changes and delete the directory.
    for fname in prj_path.iterdir():
        # Do not push .osc directory
        if ".osc" in str(fname):
            continue
        with open(fname, "rb") as fdata:
            osc.packages.push_file(prj, "klp", fname.name, fdata.read())
    osc.packages.cmd(prj, "klp", "commit", comment=f"Dump {branch}")
    shutil.rmtree(prj_path)

    logging.info("(%d/%d) %s done", i, total, cs.full_cs_name())


def push(lp_name, lp_filter, wait=False):
    cs_list = filter_codestreams(lp_filter, get_codestreams_dict())

    if not cs_list:
        logging.error("push: No codestreams found for %s", lp_name)
        sys.exit(1)

    logging.info("Pushing %d codestreams: %s", len(cs_list),
                 classify_codestreams_str(cs_list))

    osc = Osc(url="https://api.suse.de")

    total = len(cs_list)
    i = 1
    # More threads makes OBS to return error 500
    for cs in cs_list:
        create_lp_package(osc, lp_name, i, total, cs)
        i += 1

    if wait:
        # Give some time for IBS to start building the last pushed
        # codestreams
        time.sleep(30)
        status(lp_name, lp_filter, wait)

        # One more status after everything finished, since we remove
        # finished builds on each iteration
        status(lp_name, lp_filter, False)


def run(lp_name, lp_filter, wait=False):
    push(lp_name, lp_filter, wait)
