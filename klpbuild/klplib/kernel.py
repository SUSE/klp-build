# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import logging
import os
import re
import shutil
import subprocess
import atexit
from functools import wraps
from multiprocessing import Lock
from pathlib import Path

from klpbuild.klplib.config import get_user_path, get_repos_dir

TREE_NAME = "kernel"

__KERNEL_PATH = None
__KERNEL_FS = None
__KERNEL_TAGS_ARE_FETCHED = False
__kernel_fetch_lock = Lock()
__kernel_init_lock = Lock()
__kernel_fs_init_lock = Lock()


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
        global __KERNEL_TAGS_ARE_FETCHED

        with __kernel_fetch_lock:
            if not __KERNEL_TAGS_ARE_FETCHED:
                __fetch_kernel_tree_tags()
                __KERNEL_TAGS_ARE_FETCHED = True
        return func(*args, **kwargs)

    return wrapper


def __fetch_kernel_tree_tags():
    """
    Fetch and update the list of tags in the kernel repository.
    """
    logging.debug("Updating kernel tree tags..")
    kernel_tree = get_user_path("kernel_dir")
    ret = subprocess.run(
        ["git", "-C", kernel_tree, "fetch", "--tags", "--force", "--quiet"],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        check=False,
        text=True,
    )
    if ret.returncode:
        logging.info("Failed to update kernel tree tags\n%s", ret.stderr)


@__check_kernel_tags_are_fetched
def __init_kernel():
    global __KERNEL_PATH

    with __kernel_init_lock:
        if __KERNEL_PATH:
            return

        git_path = get_repos_dir() / TREE_NAME / "git"

        if not os.path.isdir(git_path):
            os.makedirs(git_path.parent, exist_ok=True)
            subprocess.check_output(
                ["git", "worktree", "add", "-f", git_path],
                cwd=get_user_path("kernel_dir"),
                stderr=subprocess.STDOUT,
            )
        else:
            subprocess.check_output(
                ["git", "checkout", "-f", TREE_NAME],
                cwd=git_path,
                stderr=subprocess.STDOUT,
            )

        __KERNEL_PATH = git_path


def __init_kernel_fs():
    global __KERNEL_FS

    with __kernel_fs_init_lock:
        if __KERNEL_FS:
            return

        fs_path = get_repos_dir() / TREE_NAME / "fs"

        if os.path.ismount(fs_path):
            logging.warning("%s: already mounted", str(fs_path))
            __KERNEL_FS = fs_path
            return

        gitfs_bin = shutil.which("git-fs")
        if not gitfs_bin:
            logging.warning(
                "git-fs binary not found. Install git-fs to enable "
                "FUSE-based kernel tree access."
            )
            return

        os.makedirs(fs_path, exist_ok=True)

        kernel_tree = get_user_path("kernel_dir")

        subprocess.check_output(
            [gitfs_bin, "-m", str(fs_path), "-a"],
            stderr=subprocess.STDOUT,
            cwd=kernel_tree,
        )

        __KERNEL_FS = fs_path

        logging.debug("%s: successfully mounted", str(__KERNEL_FS))



@atexit.register
def __fini_kernel_fs():
    """
    Unmount the git filesystem on exit().
    """

    if not __KERNEL_FS or not os.path.ismount(__KERNEL_FS):
        return

    subprocess.check_output(
        ["git", "fs", "-u", str(__KERNEL_FS)],
        stderr=subprocess.STDOUT,
    )

    os.rmdir(__KERNEL_FS)

    logging.debug("%s: successfully unmounted", str(__KERNEL_FS))


def __get_kernel():
    if not __KERNEL_PATH:
        __init_kernel()
    return __KERNEL_PATH


def __get_kernel_fs():
    if not __KERNEL_FS:
        __init_kernel_fs()
    return __KERNEL_FS


def get_kernel_tag_path(kernel_version):
    return __get_kernel_fs() / "tags" / ("rpm-" + kernel_version) / "tree"


def get_kernel_branch_path(branch, remote="origin"):
    return __get_kernel_fs() / "branches" / "remotes" / remote / branch / "tree"


def __lp_branch_name(lp_name, cs):
    return lp_name + "_" + cs.full_cs_name()


def get_lp_branch_path(lp_name, cs):
    return __get_kernel_fs() / "branches" / "heads" / __lp_branch_name(lp_name, cs) / "tree"


# Currently this function returns the date of the patch, its subject
# and the hash of the corresponding commit in kernel-source.
@__check_kernel_tags_are_fetched
def get_commit_data(commit, savedir=None):
    kernel_tree = get_user_path("kernel_dir")

    ret = subprocess.check_output(
        ["/usr/bin/git", "-C", kernel_tree, "show",
         commit, "--format='%at@%s%n%n%B'"]
    ).decode().splitlines()
    head = ret[0].split("@")
    date = head[0]
    title = head[1]
    body = ret[1:]
    suse_commit = re.search(
        r"suse-commit:\s*([a-z0-9]{40})|$", "\n".join(body)
    ).group(1)

    # Save the upstream commit if requested
    if savedir:
        with open(Path(savedir, f"{commit}.patch"), "w") as f:
            f.write("\n".join(body))

    return date, title, suse_commit


@__check_kernel_tags_are_fetched
def get_commit_body(commit, file_path):
    """
    Get the changes done to the given file in a specific commit.
    For each change, the whole function is returned as context.
    """

    kernel_tree = get_user_path("kernel_dir")

    ret = subprocess.run(
        ["git", "-C", kernel_tree, "show", "-W",
         "--pretty='%b'", commit, "--", file_path],
        check=True,
        capture_output=True,
        text=True,
    )
    return ret.stdout


@__check_kernel_tags_are_fetched
def find_commit(subject, branch, skip=0):
    """
    Find a commit by subject. Skip, if specified, the first 'n'
    found commits.

    Returns:
        - (str) Commit hash on success.
        - None otherwise.
    """

    kernel_tree = get_user_path("kernel_dir")

    while True:
        try:
            ret = subprocess.run(
                ["git", "-C", kernel_tree, "log", "-n1",
                 f"--grep=^{subject}", rf"--grep=-\s*{subject}",
                 "--pretty='%h'", f"--skip={skip}",
                 f"remotes/origin/{branch}"],
                capture_output=True,
                check=False,
                text=True,
                timeout=1,
            )
            return ret.stdout.replace("'", "").strip()
        except subprocess.TimeoutExpired:
            # Sometimes the subject doesn't match due to unexpected line breaks in
            # the commit's subject.
            # Unfortunatly, git-log cannot grep more than one line at a time, so
            # as workaround we have to trim long subjects and re-try.
            if len(subject) <= 40:
                break
            # Cut off the last two words of the subject.
            subject = subject.rsplit(" ", 2)[0]

    logging.debug("Failed to find the kernel commit for '%s'", subject)

    return None


@__check_kernel_tags_are_fetched
def file_exists_in_tag(kernel_version, file_path):
    """
    Check if a specific file exists in a given kernel version tag.

    Args:
        kernel_version (str): Kernel version to check.
        file_path (str): Path of the file to verify.

    Returns:
        True if exists. False otherwise.
    """
    return (get_kernel_tag_path(kernel_version) / file_path).exists()


def read_file_in_tag(kernel_version, file_path):
    return (get_kernel_tag_path(kernel_version) / file_path).read_text()


def abort_patch():
    subprocess.run(
        ["git", "am", "--abort"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=__get_kernel(),
        check=False,
    )


def __checkout_tag(kernel_version):
    err = subprocess.run(
        ["git", "checkout", "-f", f"rpm-{kernel_version}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=__get_kernel(),
        check=False,
    )
    if err.returncode != 0:
        raise RuntimeError(f"Failed to switch to rpm-{kernel_version} tag. Aborting\n")


def create_lp_branch(lp_name, cs):
    __checkout_tag(cs.kernel)
    branch = __lp_branch_name(lp_name, cs)
    err = subprocess.run(
        ["git", "checkout", "-B", branch],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=__get_kernel(),
        check=False,
    )
    if err.returncode != 0:
        raise RuntimeError(f"Failed to create branch {branch}. Aborting")


def delete_lp_branch(lp_name, cs):
    __checkout_tag(cs.kernel)
    branch = __lp_branch_name(lp_name, cs)
    err = subprocess.run(
        ["git", "branch", "-D", branch],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=__get_kernel(),
        check=False,
    )
    if err.returncode != 0 and f"'{branch}' not found" not in str(err.stderr):
        raise RuntimeError(f"Failed to delete branch {branch}:\n{err.stderr}\n")


def apply_patch(patch):
    sdir = __get_kernel()
    # Try to apply the patch first with git-am.
    # Beware that git-am will not work in all cases,
    # as it is more strict than patch(1).
    err = subprocess.run(
        ["git", "am", patch],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=sdir,
        check=False,
    )
    if err.returncode == 0:
        return True

    # Failed to apply the patch with git-am, so now we are in
    # a conflict state. Fallback to patch(1) and hope for the best!
    # If patch(1) resolved the conflict, commit the changes and continue
    # with git-am. Otherwise, exit so that the user can manually fix it.
    err = subprocess.run(
        ["patch", "-s", "-f", "-p1", "-i", patch],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=sdir,
        check=False,
    )
    if err.returncode != 0:
        return False

    subprocess.run(
        ["git", "add", "."],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=sdir,
        check=False,
    )

    subprocess.run(
        ["git", "am", "--continue"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=sdir,
        check=False,
    )

    return True
