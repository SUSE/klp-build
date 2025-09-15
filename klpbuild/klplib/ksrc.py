# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import re
import subprocess
import sys
from pathlib import Path
from pathlib import PurePath

from functools import wraps

from klpbuild.klplib import utils
from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.kernel_tree import get_commit_data

KERNEL_BRANCHES = {
    "12.5": "SLE12-SP5",
    "15.3": "SLE15-SP3-LTSS",
    "15.4": "SLE15-SP4-LTSS",
    "15.5": "SLE15-SP5-LTSS",
    "15.6": "SLE15-SP6",
    "15.6rt": "SLE15-SP6-RT",
    "15.7": "SLE15-SP7",
    "15.7rt": "SLE15-SP7-RT",
    "16.0": "SL-16.0",
    "16.0rt": "SL-16.0",
    "6.0": "SUSE-2024",
    "6.0rt": "SUSE-2024-RT",
    "cve-5.3": "cve/linux-5.3-LTSS",
    "cve-5.14": "cve/linux-5.14-LTSS",
} if not utils.in_test_mode() else {
    "15.3": "SLE15-SP3-RT-LTSS",
    "15.4": "SLE15-SP4-RT-LTSS",
    "15.5": "SLE15-SP5-RT-LTSS",
    "15.6": "SLE15-SP6",
    "15.6rt": "SLE15-SP6-RT",
    "15.7": "SLE15-SP7",
    "15.7rt": "SLE15-SP7-RT",
    "16.0": "SL-16.0",
    "16.0rt": "SL-16.0",
    "6.0": "SUSE-2024",
    "6.0rt": "SUSE-2024-RT",
}


__kernel_source_tags_are_fetched = False
def __check_kernel_source_tags_are_fetched(func):
    """
    This decorator checks whether the kernel-source tags are fetched. If not,
    it fetches them the configuration and then calls the wrapped function.

    Args:
        func (function): The function to be wrapped.

    Returns:
        function: The wrapped function.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        global __kernel_source_tags_are_fetched
        if not __kernel_source_tags_are_fetched:
            __fetch_kernel_branches()
            __kernel_source_tags_are_fetched = True
        return func(*args, **kwargs)
    return wrapper


def __fetch_kernel_branches():
    kern_src = get_user_path('kernel_src_dir')
    logging.info("Fetching changes from all supported branches...")

    if utils.in_test_mode():
        return

    # Mount the command to fetch all branches for supported codestreams
    ret = subprocess.run(["/usr/bin/git", "-C", kern_src, "fetch",
                          "--quiet", "--atomic", "--force", "--tags"],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         text=True)
    if ret.returncode:
        logging.info("Fetch failed\n%s", ret.stderr)


def get_patch_files(patches, branch):
    """
    Get the kernel files that have been modified by the give list of patches.

    Args:
        patches (list): Input list of patches to analyse.
        branch (str): Branch where to locate the given patches.

    returns:
        List: Return the files modified by the given patches.
    """
    kern_src = get_user_path('kernel_src_dir')

    files = []
    for p in patches:
        ret = subprocess.check_output(["/usr/bin/git", "-C", kern_src,
                                       "grep", "-Ih", "^+++",
                                       f"remotes/origin/{branch}:{p}"]).decode()
        for l in ret.splitlines():
            # Remove the first caracters "+++ [a,b]/" in the line. Leftovers
            # from the patch's diff.
            files.append(l[6:])

    return sorted(set(files))


def store_patch(pfile, patch, savedir, savedir_idx, bc):
    # removing the patches.suse dir from the filepath
    basename = PurePath(patch).name.replace(".patch", "")
    branch_path = Path(savedir)/"fixes"/bc
    branch_path.mkdir(exist_ok=True, parents=True)
    # Save the patch for later review from the livepatch developer
    with open(Path(branch_path, f"{savedir_idx:02d}-{basename}.patch"), "w") as f:
        f.write(pfile)


def get_branch_patches(cve, mbranch):
    kern_src = get_user_path('kernel_src_dir')

    try:
        patch_files = subprocess.check_output(
            ["/usr/bin/git", "-C", kern_src, "grep", "-l", f"CVE-{cve}",
             f"remotes/origin/{mbranch}", "--", "patches.suse/"],
            stderr=subprocess.STDOUT,
        ).decode(sys.stdout.encoding)
    except subprocess.CalledProcessError:
        # If we don't find any commits for RT branchs, try with the non-RT variant.
        return [] if "RT" not in mbranch else get_branch_patches(cve, mbranch.replace("-RT", ""))

    # Prepare command to extract correct ordering of patches
    cmd = ["/usr/bin/git", "-C", kern_src, "grep", "-o", "-h"]
    for patch in patch_files.splitlines():
        _, fname = patch.split(":")
        cmd.append("-e")
        cmd.append(fname)
    cmd += [f"remotes/origin/{mbranch}:series.conf"]

    # Now execute the command
    try:
        patch_files = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode(sys.stdout.encoding)
    except subprocess.CalledProcessError:
        patch_files = ""

    return patch_files.splitlines()


@__check_kernel_source_tags_are_fetched
def get_patches(cve, savedir=None):
    logging.info("Getting SUSE fixes for upstream commits per CVE branch. It can take some time...")

    # Store all patches from each branch and upstream
    patches = {}
    patches["upstream"] = []
    # Temporal list of upstream commits
    upstream = set()

    upstream_patches_dir = None
    if savedir:
        upstream_patches_dir = Path(savedir)/"upstream"
        upstream_patches_dir.mkdir(exist_ok=True, parents=True)

    for bc, mbranch in KERNEL_BRANCHES.items():
        # Skip 16.0rt as it will have the same patches of 16.0
        # TODO: Find a better way to handle this situation
        if bc == "16.0rt":
            continue

        logging.debug("	processing %s:%s", bc, mbranch)
        patches[bc] = []

        idx = 0
        for patch in get_branch_patches(cve, mbranch):
            if patch.strip().startswith("#"):
                continue

            idx += 1

            pfile = ksrc_read_branch_file(mbranch, patch)
            if not pfile:
                continue

            if savedir:
                store_patch(pfile, patch, savedir, idx, bc)

            # Get the upstream commit and save it. The Git-commit can be
            # missing from the patch if the commit is not backporting the
            # upstream fix, and is using a different way to mimic the fix.
            # In this case add a note for the livepatch author to fill the
            # blank when finishing the livepatch
            ups = ""
            m = re.search(r"Git-commit: ([\w]+)", pfile)
            if m:
                c = m.group(1)[:12]
                d, msg = get_commit_data(c, upstream_patches_dir)
                upstream.add((d, c, msg))

            patches[bc].append(patch)

    # Both codestreams point to the same kernel-sources
    patches["16.0rt"] = patches["16.0"][:]

    for key, bc_patches in patches.items():
        if key == "upstream":
            continue

        logging.info(f"{key}: {KERNEL_BRANCHES[key]}")

        if not bc_patches:
            logging.info("None")
        for c in bc_patches:
            logging.info(c)
        logging.info("")

    logging.info(f"upstream")
    for _, c, msg in sorted(upstream):
        fmt = f'{c} ("{msg}")'
        patches["upstream"].append(fmt)
        logging.info(fmt)

    logging.info("")

    return patches


def get_patched_kernels(codestreams, patches):
    if not patches:
        return []

    logging.info("Searching for already patched codestreams...")

    kernels = set()

    for cs in codestreams:
        bc = cs.full_cs_name().split("u")[0]
        suse_patches = patches[bc]
        if not suse_patches:
            continue

        # Proceed to analyse each codestream's kernel
        kernel = cs.kernel

        logging.debug(f"\n{cs.full_cs_name()} ({kernel}):")
        for patch in suse_patches:
            if not ksrc_read_rpm_file(kernel, patch):
                break
            logging.debug(f"{patch}")
        else:
            kernels.add(kernel)

    logging.debug("")

    return kernels


def cs_is_affected(cs, cve, patches):
    # We can only check if the cs is affected or not if the CVE was informed
    # (so we can get all commits related to that specific CVE). Otherwise we
    # consider all codestreams as affected.
    if not cve:
        return True

    return len(patches[cs.base_cs_name()]) > 0


def ksrc_read_rpm_file(kernel_version, file_path):
    return __read_file("rpm-" + kernel_version, file_path)


def ksrc_read_branch_file(branch, file_path):
    return __read_file("remotes/origin/" + branch, file_path)


def __read_file(ref, file_path):
    ksrc_dir = get_user_path("kernel_src_dir")

    ret = subprocess.run(["git", "-C", ksrc_dir, "show",
                          f"{ref}:{file_path}"],
                         capture_output=True, text=True)
    return ret.stdout


def ksrc_is_module_supported(module, kernel):
    """
    Check if a kernel module is supported on a specific kernel.
    This is done by reading the 'supported.conf' file.

    Args:
        module (str): Full path of the module.
        kernel (sr): Kernel version.

    returns:
        Return True if supported. False otherwise.
        """
    UNSUPPORTED_MARKERS = {
        "-",
        "+external",
        "-!optional"
    }

    mpath = module
    prev = ""
    idx = 1

    out = ksrc_read_rpm_file(kernel, "supported.conf").splitlines()
    if not out:
        return False

    # Try the following path combinations to see if it matches with
    # any rule in the supported.conf:
    #   my/kernel/module/path
    #   my/kernel/module/*
    #   my/kernel/*
    #   my/*
    while mpath != prev:
        r = re.compile(rf"^([-+]!?\w*)?\s+{mpath}")
        matches = [m for line in out if (m := r.match(line))]

        # Try more generic path if we don't match
        if not matches:
            prev = mpath
            mpath = module.rsplit("/", idx)[0] + r"/\*"
            idx += 1
            continue

        # At this point we've surely matched. Check if we support it or not.
        markers = [marker for match in matches if (marker := match.group(1))]
        if len(markers) > 1:
            raise RuntimeError(f"ERROR: matched more than one line in {kernel}:supported.conf")

        # Line has matched but there's no marker -> module is supported
        if not markers:
            return True

        # Check if any marker belongs to UNSUPPORTED_MARKERS
        if markers[0] in UNSUPPORTED_MARKERS:
            return False

        raise RuntimeError(f"ERROR: marker {marker} in {kernel}:supported.conf is not known!")

    return True
