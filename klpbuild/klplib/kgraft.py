# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

import logging
import subprocess
import os
import re

from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.utils import get_workdir

TREE_NAME = "kgraft"
__kgr_path = ""


def init_kgraft():
    global __kgr_path
    data_path = get_user_path('data_dir')
    __kgr_path = data_path/TREE_NAME

    if not os.path.isdir(__kgr_path):
        subprocess.check_output(
                ["git", "worktree", "add", "-f", __kgr_path],
                cwd=get_user_path('kgr_patches_dir'),
                stderr=subprocess.STDOUT,
                )
    else:
        subprocess.check_output(
                ["git", "checkout", "-f", TREE_NAME],
                cwd=__kgr_path,
                stderr=subprocess.STDOUT,
                )


def get_kgraft():
    global __kgr_path
    return __kgr_path


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

    subprocess.check_output(
            ["git", "checkout", "-f", TREE_NAME],
            cwd=get_kgraft(),
            stderr=subprocess.STDOUT,
            )

    for bname in branches:
        err = subprocess.run(["git", "branch", "-D", bname], cwd=get_kgraft(),
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE,
                             text=True, check=False)
        if "used by worktree" not in str(err.stderr):
            logging.warning(f"Failed to delete branch: {bname}: {err.stderr}")


def create_lp_branch(branch, base="origin/master-livepatch"):
    subprocess.check_output(
            ["git", "checkout", "-f",
             "--ignore-other-worktrees", "-B",
             branch, base],
            cwd=get_kgraft(),
            stderr=subprocess.STDOUT,
            )


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
