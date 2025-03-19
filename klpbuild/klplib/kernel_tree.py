# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import logging
import os
import subprocess

from klpbuild.klplib.config import get_user_path

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

