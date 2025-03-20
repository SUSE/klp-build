# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import logging
import os
import shutil
import subprocess

from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.utils import ARCH


def init_cs_kernel_tree(kernel_version, outdir):
    """
    Initialize a kernel source worktree for a specific kernel version.

    This function checks out the appropriate git branch based on the kernel version
    and creates a worktree in the specified output directory.

    Args:
        kernel_version (str): Kernel version to check out.
        outdir (str): Directory where the kernel worktree should be placed.
    """
    kernel_tree = get_user_path("kernel_dir")
    kernel_tree_git_tag = "rpm-" + kernel_version

    # NOTE: here using something like
    #       if 'outdir' in __get_active_worktrees():
    # doesn't work. Most likely this is not atomic. Perhaps using a
    # per-worktree lock would be a better idea
    if not os.path.isdir(outdir):
        logging.info("Checking out source tree: %s", outdir)
        subprocess.check_output([
            "/usr/bin/git", "-C", kernel_tree, "worktree",
            "add", outdir, "--checkout", kernel_tree_git_tag
        ], stderr=subprocess.PIPE)


def cleanup_kernel_trees():
    """
    Remove kernel source trees.
    """
    kernel_tree = get_user_path("kernel_dir")
    worktrees = __get_active_worktrees(kernel_tree)

    for wt in worktrees:
        logging.info("Removing worktree %s", wt)
        __remove_worktree(kernel_tree, wt)

    # Sometimes when git-worktree is killed during the checkout of the worktree
    # there are pending sources which are not registered as worktree
    sources_dir = get_user_path("data_dir")/ARCH/"usr"/"src"
    for entry in os.listdir(sources_dir):
        full_path = sources_dir/entry
        if os.path.isdir(full_path) and not entry.endswith("-obj"):
            logging.info(f"Removing pending kernel tree: {full_path}")
            shutil.rmtree(full_path)

    __prune_worktrees(kernel_tree)
    assert not __get_active_worktrees(kernel_tree)


def file_exists_in_tag(kernel_version, file_path):
    """
    Check if a specific file exists in a given kernel version tag.

    Args:
        kernel_version (str): Kernel version to check.
        file_path (str): Path of the file to verify.

    Returns:
        None (raises an error if the file does not exist).
    """
    kernel_tree = get_user_path("kernel_dir")
    kernel_tree_git_tag = "rpm-" + kernel_version

    subprocess.check_output([
        'git',  "-C", kernel_tree, 'ls-tree', kernel_tree_git_tag, file_path
    ], stderr=subprocess.PIPE)


def __get_active_worktrees(kernel_tree):
    data_dir = str(get_user_path("data_dir"))
    worktrees_output = subprocess.run(["git", "-C", kernel_tree, "worktree", "list"], capture_output=True, text=True)

    worktrees = []
    for line in worktrees_output.stdout.strip().split("\n"):
        if data_dir not in line:
            continue
        if "prunable" in line:
            continue
        worktrees.append(line.split()[0])

    return worktrees


def __remove_worktree(kernel_tree, worktree_dir):
    subprocess.check_output([ "/usr/bin/git", "-C", kernel_tree, "worktree",
                             "remove", worktree_dir, "-f", "-f"],
                            stderr=subprocess.PIPE)

    if os.path.isdir(worktree_dir):
        shutil.rmtree(worktree_dir)


def __prune_worktrees(kernel_tree):
    logging.debug("Pruning pending kernel worktrees")
    subprocess.check_output([ "/usr/bin/git", "-C", kernel_tree, "worktree",
                             "prune"],
                            stderr=subprocess.PIPE)
