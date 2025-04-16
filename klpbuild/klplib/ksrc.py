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
    "6.0": "SUSE-2024",
    "6.0rt": "SUSE-2024-RT",
}

class GitHelper():

    def fetch_kernel_branches(self):
        kern_src = get_user_path('kernel_src_dir')
        logging.info("Fetching changes from all supported branches...")

        if not utils.in_test_mode():
            # Mount the command to fetch all branches for supported codestreams
            subprocess.check_output(["/usr/bin/git", "-C", str(kern_src), "fetch",
                                     "--quiet", "--atomic", "--force", "--tags", "origin"] +
                                    list(KERNEL_BRANCHES.values()))


    def diff_commits(self, base, new, patch, pattern=""):
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

    def get_commit_files(self, commit, regex=None):
        """
        Get the files that have been modified in one specific commit.
        Optionally only get those that match the given regular expression.

        Args:
            commit (str): The commit to be anylized.
            regex (str): Optional regex.

        returns:
            List: Return the files that match the regex, if set. Otherwise,
            return all the files.
        """
        kern_src = get_user_path('kernel_src_dir')

        ret = subprocess.check_output(["/usr/bin/git", "-C", kern_src,
                                       "diff-tree", "--no-commit-id", "--name-only",
                                       commit, "-r"]).decode()

        return re.findall(regex, ret) if regex else ret.splitlines()

    def get_commits(self, cve, savedir=None):
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

        self.fetch_kernel_branches()

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

            try:
                patch_files = subprocess.check_output(
                    ["/usr/bin/git", "-C", kern_src, "grep", "-l", f"CVE-{cve}", f"remotes/origin/{mbranch}"],
                    stderr=subprocess.STDOUT,
                ).decode(sys.stdout.encoding)
            except subprocess.CalledProcessError:
                patch_files = ""

            # If we don't find any commits, add a note about it
            if not patch_files:
                continue

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
            idx = 0
            for patch in patch_files.splitlines():
                if patch.strip().startswith("#"):
                    continue

                idx += 1

                pfile = subprocess.check_output(
                    ["/usr/bin/git", "-C", kern_src, "show", f"remotes/origin/{mbranch}:{patch}"],
                    stderr=subprocess.STDOUT,
                ).decode(sys.stdout.encoding)

                # removing the patches.suse dir from the filepath
                basename = PurePath(patch).name.replace(".patch", "")

                if savedir:
                    branch_path = Path(savedir)/"fixes"/bc
                    branch_path.mkdir(exist_ok=True, parents=True)
                    # Save the patch for later review from the livepatch developer
                    with open(Path(branch_path, f"{idx:02d}-{basename}.patch"), "w") as f:
                        f.write(pfile)

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

                # Now get all commits related to that file on that branch,
                # including the "Refresh" ones.
                try:
                    phashes = subprocess.check_output(
                        [
                            "/usr/bin/git",
                            "-C",
                            kern_src,
                            "log",
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
                    logging.warn(
                        f"File {fname} doesn't exists {mbranch}. It could "
                        " be removed, so the branch is not affected by the issue."
                    )
                    commits[bc]["commits"] = ["Not affected"]
                    continue

                iphashes = iter(phashes.splitlines())
                base = ""
                for hash_entry in iphashes:
                    stats = next(iphashes)

                    # Skip the Update commits, that only change the References tag
                    if "Update" in hash_entry and "patches.suse" in hash_entry:
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
                    if hash_commit in commits[bc]["commits"]:
                        continue

                    diff = self.diff_commits(base, hash_commit, patch, r"-G'^\+|^-'")
                    # Skip commit if the file's content is the same as the previous one.
                    if not diff:
                        continue

                    base = hash_commit
                    commits[bc]["commits"].append(hash_commit)

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

    def get_patched_tags(self, suse_commits):
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

    def is_kernel_patched(self, kernel, suse_commits, cve):
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

            files = self.get_commit_files(c, r"patches\.suse\/.+\.patch")
            if len(files) == 0:
                continue

            # Match 1:1 with the commits found in SLE branch
            for s in suse_commits:
                diff = self.diff_commits(s, c, files)
                if not diff:
                    # Found same commit
                    commits.append(c)
                    break

        # "patched kernels" are those which contain all commits.
        return len(suse_commits) == len(commits), commits

    def get_patched_kernels(self, codestreams, commits, cve):
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
            suse_tags = self.get_patched_tags(suse_commits)

            # Proceed to analyse each codestream's kernel
            for cs in codestreams:
                if bc+'u' not in cs.name():
                    continue

                kernel = cs.kernel
                patched, kern_commits = self.is_kernel_patched(kernel, suse_commits, cve)
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


    @staticmethod
    def cs_is_affected(cs, cve, commits):
        # We can only check if the cs is affected or not if the CVE was informed
        # (so we can get all commits related to that specific CVE). Otherwise we
        # consider all codestreams as affected.
        if not cve:
            return True

        return len(commits[cs.name_cs()]["commits"]) > 0

