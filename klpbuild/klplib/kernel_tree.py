# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import logging
import os
import shutil
import subprocess

from multiprocessing import Lock
from functools import wraps
from pathlib import Path
from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.utils import ARCH

__kernel_tags_are_fetched = False
__kernel_fetch_lock = Lock()

def __check_kernel_tags_are_fetched(func):
    """
    This decorator checks whether the kernel tags are fetched in a thread-safe
    way. If not, it fetches them the configuration and then calls the wrapped function.

    Args:
        func (function): The function to be wrapped.

    Returns:
        function: The wrapped function.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        global __kernel_tags_are_fetched
        global __kernel_fetch_lock

        with __kernel_fetch_lock:
            if not __kernel_tags_are_fetched:
                __fetch_kernel_tree_tags()
                __kernel_tags_are_fetched = True
        return func(*args, **kwargs)
    return wrapper


def __fetch_kernel_tree_tags():
    """
    Fetch and update the list of tags in the kernel repository.
    """
    logging.debug("Updating kernel tree tags..")
    kernel_tree = get_user_path("kernel_dir")
    ret = subprocess.run(['git', "-C", kernel_tree, 'fetch', '--tags', '--force', '--quiet'],
                         stderr=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         check=False,
                         text=True)
    if ret.returncode:
        logging.info("Failed to update kernel tree tags\n%s", ret.stderr)


# Currently this function returns the date of the patch and its subject
@__check_kernel_tags_are_fetched
def get_commit_data(commit, savedir=None):

    kernel_tree = get_user_path("kernel_dir")

    ret = subprocess.check_output(["/usr/bin/git", "-C", kernel_tree,
                                   "show", commit,
                                   "--format='%at@%s%n%n%B'"]).decode().splitlines()
    head = ret[0].split('@')
    date = head[0]
    title = head[1]
    body = ret[1:]

    # Save the upstream commit if requested
    if savedir:
        with open(Path(savedir, f"{commit}.patch"), "w") as f:
            f.write('\n'.join(body))

    return date, title


@__check_kernel_tags_are_fetched
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
            logging.info("Removing pending kernel tree: %s", full_path)
            shutil.rmtree(full_path)

    __prune_worktrees(kernel_tree)
    assert not __get_active_worktrees(kernel_tree)


@__check_kernel_tags_are_fetched
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

    ret = subprocess.check_output(['git',  "-C", kernel_tree, 'ls-tree',
                                   kernel_tree_git_tag, file_path],
                                  stderr=subprocess.PIPE)
    return len(ret)


def read_file_in_tag(kernel_version, file_path):

    kernel_tree = get_user_path("kernel_dir")
    kernel_tree_git_tag = "rpm-" + kernel_version

    ret = subprocess.run(["git", "-C", kernel_tree, "show", f"{kernel_tree_git_tag}:{file_path}"],
                         check=False, capture_output=True, text=True)
    return ret.stdout


def __get_active_worktrees(kernel_tree):
    data_dir = str(get_user_path("data_dir"))
    worktrees_output = subprocess.run(["git", "-C", kernel_tree, "worktree", "list"],
                                      capture_output=True, check=False, text=True)

    worktrees = []
    for line in worktrees_output.stdout.strip().split("\n"):
        if data_dir not in line:
            continue
        if "prunable" in line:
            continue
        worktrees.append(line.split()[0])

    return worktrees


def __remove_worktree(kernel_tree, worktree_dir):
    subprocess.check_output(["/usr/bin/git", "-C", kernel_tree, "worktree",
                             "remove", worktree_dir, "-f", "-f"],
                            stderr=subprocess.PIPE)

    if os.path.isdir(worktree_dir):
        shutil.rmtree(worktree_dir)


def __prune_worktrees(kernel_tree):
    logging.debug("Pruning pending kernel worktrees")
    subprocess.check_output(["/usr/bin/git", "-C", kernel_tree, "worktree",
                             "prune"],
                            stderr=subprocess.PIPE)
