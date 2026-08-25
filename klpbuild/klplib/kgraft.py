# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

import logging
import subprocess
import os
import re
import glob
import tarfile
import shutil

from pathlib import Path
from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.utils import get_workdir
from klpbuild.klplib.config import get_user_settings

TREE_NAME = "kgraft"
__KGR_PATH = ""


def init_kgraft():
    global __KGR_PATH
    data_path = get_user_path('data_dir')
    __KGR_PATH = data_path/TREE_NAME

    if not os.path.isdir(__KGR_PATH):
        subprocess.check_output(
                ["git", "worktree", "add", "-f", __KGR_PATH],
                cwd=get_user_path('kgr_patches_dir'),
                stderr=subprocess.STDOUT,
                )
    else:
        subprocess.check_output(
                ["git", "checkout", "-f", TREE_NAME],
                cwd=__KGR_PATH,
                stderr=subprocess.STDOUT,
                )


def get_kgraft():
    return __KGR_PATH


def reset_kgraft():
    '''
        Checkout to the worktree's main branch
    '''
    subprocess.check_output(
            ["git", "checkout", "-f", TREE_NAME],
            cwd=get_kgraft(),
            stderr=subprocess.STDOUT,
            )


def fetch_branch(branch, remote="origin"):
    subprocess.check_output(
        ["git", "fetch", remote, branch],
        stderr=subprocess.STDOUT, cwd=get_kgraft()
        )


def rebase_lp_branch(branch, new_base, remote="origin"):
    new_base = f"{remote}/{new_base}"
    subprocess.check_output(
            ["git", "rebase", new_base, branch],
            stderr=subprocess.STDOUT, cwd=get_kgraft()
            )


def find_lp_branches(pattern):
    err = subprocess.run(["git", "branch", "--list", pattern],
                         cwd=get_kgraft(),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True,
                         check=False)
    if err.stderr or not err.stdout:
        return None

    return [re.sub(r"[\s\*\+]",'', l) for l in err.stdout.splitlines()]


def delete_lp_branches(branches):
    if not branches:
        return

    reset_kgraft()

    for bname in branches:
        err = subprocess.run(["git", "branch", "-D", bname], cwd=get_kgraft(),
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE,
                             text=True, check=False)
        if err.stderr:
            logging.warning("Failed to delete branch: %s: %s", bname, err.stderr)


def create_lp_branch(branch, base="origin/master-livepatch"):
    subprocess.check_output(
            ["git", "checkout", "-f",
             "--ignore-other-worktrees", "-B",
             branch, base],
            cwd=get_kgraft(),
            stderr=subprocess.STDOUT,
            )


def create_release_branch(cs, lp_branch, prefix):
    '''
        Creates the release branch for a given livepatch.
        A release branch is based in the product branch +
        the new livepatch source code. If compiled and built, it
        will generate a working livepatch kernel module.

        Returns:
            The release branch name if it was successfully created.
            'None' otherwise.
    '''
    product_branch = cs.get_full_product_name()
    release_branch = f"{prefix}/{product_branch}/{str(lp_branch)}"

    try:
        fetch_branch(product_branch)
        create_lp_branch(release_branch, lp_branch)
        rebase_lp_branch(release_branch, product_branch)
    except subprocess.CalledProcessError:
        release_branch = None

    return release_branch


def commit_lp_changes(lp_name):
    subprocess.check_output(
            ["git", "add", "."],
            cwd=get_kgraft(),
            stderr=subprocess.STDOUT,
            )
    subprocess.check_output(
            ["git", "commit",
             "--file", f"{get_workdir(lp_name)}/commit.msg"],
            cwd=get_kgraft(),
            stderr=subprocess.STDOUT,
            )


def tar_up(prj_path, version=None):
    '''
        Run the tar-up script found in all kgraft branches.
        The script will archive the livepatches and prepare the files
        for building the kernel module.
    '''
    kgr_path = get_kgraft()

    if prj_path.exists():
        shutil.rmtree(prj_path)

    if version:
        with open(Path(kgr_path, "scripts", "release-version.sh"), "w") as f:
            f.write(f"RELEASE={version}")

    subprocess.check_output(
        ["bash", "./scripts/tar-up.sh", "-d", str(prj_path)],
        cwd=kgr_path,
        stderr=subprocess.STDOUT,
    )


def make(prj_path, cs, gcc_version, gcc_log):
    '''
        Compile the livepatch kernel module for the given
        codestream. Use default `gcc` if no specific version
        is provided.

        Return:
            0 if succeeded. > 0 otherwise.
    '''
    workers = int(get_user_settings("workers"))
    sdir = cs.get_src_dir()
    odir = cs.get_obj_dir()

    # Use gcc-7 for older kernel (12.5, 15.4 and 15.5)
    if not cs.needs_ibt():
        gcc_version = 7

    cc = f"gcc-{gcc_version}" if gcc_version else "gcc"

    tar_up(prj_path)

    # Before compiling first extract all the bsc tar files.
    for tar in glob.glob(f"{prj_path}/*.tar.bz2"):
        with tarfile.open(name=tar, mode="r:bz2", ignore_zeros=True) as t:
             t.extractall(path=prj_path, filter='data')

    with open(gcc_log, "w") as log:
        err = subprocess.run(
                ["make",
                 f"KDIR={sdir}",
                 f"O={odir}",
                 f"CC={cc}",
                 f"-j{workers}"],
                cwd=prj_path,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True, check=False)

    shutil.rmtree(prj_path)

    return err.returncode
