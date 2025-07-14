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

from natsort import natsorted
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
    ret = subprocess.run(["/usr/bin/git", "-C", str(kern_src), "fetch",
                          "--quiet", "--atomic", "--force", "--tags", "origin"] +
                         list(KERNEL_BRANCHES.values()),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         text=True)
    if ret.returncode:
        logging.info("Fetch failed\n%s", ret.stderr)


def diff_commits(base, new, patch, pattern=""):
    """
    Check if there's any difference between the two given commits.

    Args:
        base (str): Commit to use as base in the diff.
        new (str): Commit to compare with the base.
        patch (list): Target files in the diff.

    returns:
        Boolean: True if both commits differ. False otherwise.
    """
    kern_src = get_user_path('kernel_src_dir')

    if base == "":
        return True

    # Compare lines starting with '+' or '-'.
    # This should be enough to ignore sneaky metadata updates on
    # the file and duplicated commits.
    diff = subprocess.run(["/usr/bin/git", "-C", kern_src, "diff",
                           "--numstat", pattern, base, new,
                           "--", str(patch)],
                          stdout = subprocess.DEVNULL,
                          stderr = subprocess.DEVNULL)

    return diff.returncode


def get_commit_files(commit, inside_patch=False, regex=r"patches\.suse\/.+\.patch"):
    """
    Get the files that have been modified in one specific commit or
    within the patch files of the commit.
    Optionally only get those that match the given regular expression.

    Args:
        commit (str): The commit to be anylized.
        regex (str): Optional regex.
        inside_path (bool): True for getting the files modified by the
        patch file in the commit. False for just getting the files in the
        commit.

    returns:
        List: Return the files that match the regex, if set. Otherwise,
        return all the files.
    """
    kern_src = get_user_path('kernel_src_dir')

    ret = subprocess.check_output(["/usr/bin/git", "-C", kern_src,
                                   "diff-tree", "--no-commit-id", "--name-only",
                                   commit, "-r"]).decode()

    patches = re.findall(regex, ret) if regex else ret.splitlines()
    if not inside_patch:
        return patches

    files = []
    for p in patches:
        ret = subprocess.check_output(["/usr/bin/git", "-C", kern_src,
                                       "grep", "-Ih", "^+++", commit,
                                       "--", p]).decode()
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
            ["/usr/bin/git", "-C", kern_src, "grep", "-l", f"CVE-{cve}", f"remotes/origin/{mbranch}"],
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

    # The command above returns a list of strings in the format
    #   branch:file/path
    return patch_files.splitlines()


def get_branch_commits(mbranch, patch):

    kern_src = get_user_path('kernel_src_dir')

    # Now get all commits related to that file on that branch,
    # including the "Refresh" ones.
    try:
        phashes = subprocess.check_output(
            [
                "/usr/bin/git",
                "-C",
                kern_src,
                "log",
                "--full-history",
                "--remove-empty",
                "--numstat",
                "--reverse",
                "--no-merges",
                "--pretty=oneline",
                f"remotes/origin/{mbranch}",
                "--",
                patch,
            ],
            stderr=subprocess.STDOUT,
        ).decode("ISO-8859-1")
    except subprocess.CalledProcessError:
        return []

    iphashes = iter(phashes.splitlines())
    base = ""
    commits = []
    for hash_entry in iphashes:
        stats = next(iphashes)

        # Skip the Update commits, that only change the References tag
        if "Update" in hash_entry and "patches.suse" in hash_entry:
            continue

        # Skip any merge commit that git's --no-merge failed to filter out
        if "Merge branch" in hash_entry:
            continue

        # Skip commits that change one single line. Most likely just a
        # reference update.
        if stats.split()[0] == "1":
            continue

        hash_commit = hash_entry.split(" ")[0]

        # Sometimes we can have a commit that touches two files. In
        # these cases we can have duplicated hash commits, since git
        # history for each individual file will show the same hash.
        # Skip if the same hash already exists.
        if hash_commit in commits:
            continue

        diff = diff_commits(base, hash_commit, patch, r"-G'^\+|^-'")
        # Skip commit if the file's content is the same as the previous one.
        if not diff:
            continue

        base = hash_commit
        commits.append(hash_commit)

    return commits


@__check_kernel_source_tags_are_fetched
def get_commits(cve, savedir=None):
    kern_src = get_user_path('kernel_src_dir', isopt=True)
    if not kern_src:
        logging.info("kernel_src_dir not found, skip getting SUSE commits")
        return {}

    # ensure that the user informed the commits at least once per 'project'
    if not cve:
        logging.info("No CVE informed, skipping the processing of getting the patches.")
        return {}

    # Support CVEs from 2020 up to 2029
    if not re.match(r"^202[0-9]-[0-9]{4,7}$", cve):
        logging.info("Invalid CVE number '%s', skipping the processing of getting the patches.", cve)
        return {}

    logging.info("Getting SUSE fixes for upstream commits per CVE branch. It can take some time...")

    # Store all commits from each branch and upstream
    commits = {}
    # List of upstream commits, in creation date order
    ucommits = []

    upstream_patches_dir = None
    if savedir:
        upstream_patches_dir = Path(savedir)/"upstream"
        upstream_patches_dir.mkdir(exist_ok=True, parents=True)

    # Get backported commits from all possible branches, in order to get
    # different versions of the same backport done in the CVE branches.
    # Since the CVE branch can be some patches "behind" the LTSS branch,
    # it's good to have both backports code at hand by the livepatch author
    for bc, mbranch in KERNEL_BRANCHES.items():
        logging.debug("	processing: %s: %s", bc, mbranch)
        commits[bc] = {"commits": []}

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
                ups = m.group(1)[:12]

            # Aggregate all upstream fixes found
            if ups and ups not in ucommits:
                ucommits.append(ups)

            c = get_branch_commits(mbranch, patch)
            if c:
                commits[bc]["commits"] = list(set(c + commits[bc]["commits"]))
            else:
                commits[bc]["commits"] = []

    # Grab each commits subject and date for each commit. The commit dates
    # will be used to sort the patches in the order they were
    # created/merged.
    ucommits_sort = []
    for c in ucommits:
        d, msg = get_commit_data(c, upstream_patches_dir)
        ucommits_sort.append((d, c, msg))

    ucommits_sort.sort()
    commits["upstream"] = {"commits": []}
    for d, c, msg in ucommits_sort:
        commits["upstream"]["commits"].append(f'{c} ("{msg}")')

    logging.info("")

    for key, val in commits.items():
        if key == "upstream":
            logging.info(f"{key}")
        else:
            logging.info(f"{key}: {KERNEL_BRANCHES[key]}")

        branch_commits = val["commits"]
        if not branch_commits:
            logging.info("None")
        for c in branch_commits:
            logging.info(c)
        logging.info("")

    return commits

def get_patched_tags(suse_commits):
    tag_commits = {}
    patched = []
    total_commits = len(suse_commits)
    kern_src = get_user_path('kernel_src_dir')

    # Grab only the first commit, since they would be put together
    # in a release either way. The order of the array is backards, the
    # first entry will be the last patch found.
    for su in suse_commits:
        tag_commits[su] = []

        tags = subprocess.check_output(["/usr/bin/git", "-C", kern_src,
                                        "tag", f"--contains={su}",
                                        "rpm-*"])

        for tag in tags.decode().splitlines():
            # Remove noise around the kernel version, like
            # rpm-5.3.18-150200.24.112--sle15-sp2-ltss-updates
            if "--" in tag:
                continue

            tag = tag.replace("rpm-", "")
            tag_commits.setdefault(tag, [])
            tag_commits[tag].append(su)

        # "patched branches" are those who contain all commits
        for tag, b in tag_commits.items():
            if len(b) == total_commits:
                patched.append(tag)

    # remove duplicates
    return natsorted(list(set(patched)))

def is_kernel_patched(kernel, suse_commits, cve):
    commits = []

    kern_src = get_user_path('kernel_src_dir')
    ret = subprocess.check_output(["/usr/bin/git", "-C", kern_src, "log",
                                   f"--grep=CVE-{cve}",
                                   f"--tags=*rpm-{kernel}",
                                   "--format='%at-%H-%s'"]).decode().splitlines()
    # Sort by date
    ret.sort(reverse=True)

    for line in ret:
        # Skip the Update commits, that only change the References tag
        if "Update" in line and "patches.suse" in line:
            continue

        # Parse commit's hash
        c = line.split("-")[1]

        files = get_commit_files(c)
        nfiles = len(files)
        if nfiles == 0:
            continue

        # Match 1:1 with the commits found in SLE branch
        for s in suse_commits:
            if nfiles <= 500:
                diff = diff_commits(s, c, files)
                if not diff:
                    # Found same commit
                    commits.append(c)
                    break
            else:
                # Do not diff commits with too many files.
                if nfiles == len(get_commit_files(s)):
                    commits.append(c)
                    break

    # "patched kernels" are those which contain all commits.
    return len(suse_commits) == len(commits), commits

def get_patched_kernels(codestreams, commits, cve):
    if not commits:
        return []

    kern_src = get_user_path('kernel_src_dir', isopt=True)
    if not kern_src:
        logging.info("kernel_src_dir not found, skip getting SUSE commits")
        return []

    if not cve:
        logging.info("No CVE informed, skipping the processing of getting the patched kernels.")
        return []

    logging.info("Searching for already patched codestreams...")

    kernels = []

    for bc, _ in KERNEL_BRANCHES.items():
        suse_commits = commits[bc]["commits"]
        if not suse_commits:
            continue

        # Get all the kernels/tags containing the commits in the main SLE
        # branch. This information alone is not reliable enough to decide
        # if a kernel is patched.
        suse_tags = get_patched_tags(suse_commits)

        # Proceed to analyse each codestream's kernel
        for cs in codestreams:
            if bc+'u' not in cs.name():
                continue

            kernel = cs.kernel
            patched, kern_commits = is_kernel_patched(kernel, suse_commits, cve)
            if not patched and kernel not in suse_tags:
                continue

            logging.debug(f"\n{cs.name()} ({kernel}):")

            # If no patches/commits were found for this kernel, fallback to
            # the commits in the main SLE branch. In either case, we can
            # assume that this kernel is already patched.
            for c in kern_commits if patched else suse_commits:
                logging.debug(f"{c}")

            kernels.append(kernel)

    logging.debug("")

    # remove duplicates
    return natsorted(list(set(kernels)))


def cs_is_affected(cs, cve, commits):
    # We can only check if the cs is affected or not if the CVE was informed
    # (so we can get all commits related to that specific CVE). Otherwise we
    # consider all codestreams as affected.
    if not cve:
        return True

    return len(commits[cs.name_cs()]["commits"]) > 0


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

    mpath = module
    prev = ""
    idx = 1
    supported = True

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
        r = re.compile(rf"^[-+\s].*{mpath}")
        match = list(filter(r.match, out))
        if match:
            supported = match[0][0] != '-'
            break

        prev = mpath
        mpath = module.rsplit("/", idx)[0] + r"/\*"
        idx += 1

    return supported
