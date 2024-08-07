# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from pathlib import PurePath

import git
import requests
from natsort import natsorted

from klpbuild.config import Config


class GitHelper(Config):
    def __init__(self, lp_name, lp_filter, kdir, data_dir):
        super().__init__(lp_name, lp_filter, kdir, data_dir)

        self.kern_src = os.getenv("KLP_KERNEL_SOURCE", "")
        if self.kern_src and not Path(self.kern_src).is_dir():
            raise ValueError("KLP_KERNEL_SOURCE should point to a directory")

        self.kernel_branches = {
            "12.5": "SLE12-SP5",
            "15.2": "SLE15-SP2-LTSS",
            "15.3": "SLE15-SP3-LTSS",
            "15.4": "SLE15-SP4-LTSS",
            "15.5": "SLE15-SP5",
            "15.5rt": "SLE15-SP5-RT",
            "15.6": "SLE15-SP6",
            "15.6rt": "SLE15-SP6-RT",
            "cve-5.3": "cve/linux-5.3-LTSS",
            "cve-5.14": "cve/linux-5.14-LTSS",
        }

        self.branches = []

        self.kgr_patches = Path(Path().home(), "kgr", "kgraft-patches")
        if not self.kgr_patches.is_dir():
            logging.warning("kgraft-patches does not exists in ~/kgr")
        else:
            # Filter only the branches related to this BSC
            repo = git.Repo(self.kgr_patches).branches
            for r in repo:
                if r.name.startswith(self.lp_name):
                    self.branches.append(r.name)

    def get_cs_branch(self, cs):
        cs_sle, sp, cs_up, rt = self.get_cs_tuple(cs)

        if not self.kgr_patches.is_dir():
            logging.warning("kgraft-patches does not exists in ~/kgr")
            return ""

        branch_name = ""

        for branch in self.branches:
            # Check if the codestream is a rt one, and if yes, apply the correct
            # separator later on
            if rt and "rt" not in branch:
                continue

            separator = "u"
            if rt:
                separator = "rtu"

            # First check if the branch has more than code stream sharing
            # the same code
            for b in branch.replace(self.lp_name + "_", "").split("_"):
                # Only check the branches that are the same type of the branch
                # being searched. Only check RT branches if the codestream is a
                # RT one.
                if rt and "rtu" not in b:
                    continue

                if not rt and "rtu" in b:
                    continue

                sle, u = b.split(separator)
                if f"{cs_sle}.{sp}" != f"{sle}":
                    continue

                # Get codestreams interval
                up = u
                down = u
                if "-" in u:
                    down, up = u.split("-")

                # Codestream between the branch codestream interval
                if cs_up >= int(down) and cs_up <= int(up):
                    branch_name = branch
                    break

                # At this point we found a match for our codestream in
                # codestreams.json, but we may have a more specialized git
                # branch later one, like:
                # bsc1197597_12.4u21-25_15.0u25-28
                # bsc1197597_15.0u25-28
                # Since 15.0 SLE uses a different kgraft-patches branch to
                # be built on. In this case, we continue to loop over the
                # other branches.

        return branch_name

    def format_patches(self, version):
        ver = f"v{version}"
        # index 1 will be the test file
        index = 2

        if not self.kgr_patches.is_dir():
            logging.warning("kgraft-patches does not exists in ~/kgr, patches will be incomplete")

        # Remove dir to avoid leftover patches with different names
        patches_dir = Path(self.lp_path, "patches")
        shutil.rmtree(patches_dir, ignore_errors=True)

        test_src = self.get_tests_path()
        subprocess.check_output(
            [
                "/usr/bin/git",
                "-C",
                str(self.kgraft_tests_path),
                "format-patch",
                "-1",
                f"{test_src}",
                "--cover-letter",
                "--start-number",
                "1",
                "--subject-prefix",
                f"PATCH {ver}",
                "--output-directory",
                f"{patches_dir}",
            ]
        )

        # Filter only the branches related to this BSC
        for branch in self.branches:
            print(branch)
            bname = branch.replace(self.lp_name + "_", "")
            bs = " ".join(bname.split("_"))
            bsc = self.lp_name.replace("bsc", "bsc#")

            prefix = f"PATCH {ver} {bsc} {bs}"

            subprocess.check_output(
                [
                    "/usr/bin/git",
                    "-C",
                    str(self.kgr_patches),
                    "format-patch",
                    "-1",
                    branch,
                    "--start-number",
                    f"{index}",
                    "--subject-prefix",
                    f"{prefix}",
                    "--output-directory",
                    f"{patches_dir}",
                ]
            )

            index += 1

    # Currently this function returns the date of the patch and it's subject
    def get_commit_data(commit, savedir=None):
        req = requests.get(f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit}")
        req.raise_for_status()

        # Save the upstream commit if requested
        if savedir:
            with open(Path(savedir, f"{commit}.patch"), "w") as f:
                f.write(req.text)

        # Search for Subject until a blank line, since commit messages can be
        # seen in multiple lines.
        msg = re.search(r"Subject: (.*?)(?:(\n\n))", req.text, re.DOTALL).group(1).replace("\n", "")
        # Sometimes the MIME-Version string comes right after the commit
        # message, so we should remove it as well
        if 'MIME-Version:' in msg:
            msg = re.sub(r"MIME-Version(.*)", "", msg)
        dstr = re.search(r"Date: ([\w\s,:]+)", req.text).group(1)
        d = datetime.strptime(dstr.strip(), "%a, %d %b %Y %H:%M:%S")

        return d, msg

    def get_commits(self, cve):
        if not self.kern_src:
            logging.info("KLP_KERNEL_SOURCE not defined, skip getting SUSE commits")
            return {}

        # ensure that the user informed the commits at least once per 'project'
        if not cve:
            logging.info(f"No CVE informed, skipping the processing of getting the patches.")
            return {}

        # Support CVEs from 2020 up to 2029
        if not re.match(r"^202[0-9]-[0-9]{4,7}$", cve):
            logging.info(f"Invalid CVE number {cve}, skipping the processing of getting the patches.")
            return {}

        print("Fetching changes from all supported branches...")

        # Mount the command to fetch all branches for supported codestreams
        args = ["/usr/bin/git", "-C", self.kern_src, "fetch", "--tags", "origin"]
        args.extend(self.kernel_branches.values())
        subprocess.check_output(args)

        print("Getting SUSE fixes for upstream commits per CVE branch. It can take some time...")

        # Store all commits from each branch and upstream
        commits = {}
        # List of upstream commits, in creation date order
        ucommits = []

        upatches = Path(self.lp_path, "upstream")
        upatches.mkdir(exist_ok=True, parents=True)

        # Get backported commits from all possible branches, in order to get
        # different versions of the same backport done in the CVE branches.
        # Since the CVE branch can be some patches "behind" the LTSS branch,
        # it's good to have both backports code at hand by the livepatch author
        for bc, mbranch in self.kernel_branches.items():
            patches = []
            commits[bc] = {"commits": []}

            try:
                patch_files = subprocess.check_output(
                    ["/usr/bin/git", "-C", self.kern_src, "grep", "-l", f"CVE-{cve}", f"remotes/origin/{mbranch}"],
                    stderr=subprocess.STDOUT,
                ).decode(sys.stdout.encoding)
            except subprocess.CalledProcessError:
                patch_files = ""

            # If we don't find any commits, add a note about it
            if not patch_files:
                continue

            # Prepare command to extract correct ordering of patches
            cmd = ["/usr/bin/git", "-C", self.kern_src, "grep", "-o", "-h"]
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
                if not patch.endswith(".patch"):
                    continue

                idx += 1
                branch_path = Path(self.lp_path, "fixes", bc)
                branch_path.mkdir(exist_ok=True, parents=True)

                pfile = subprocess.check_output(
                    ["/usr/bin/git", "-C", self.kern_src, "show", f"remotes/origin/{mbranch}:{patch}"],
                    stderr=subprocess.STDOUT,
                ).decode(sys.stdout.encoding)

                # removing the patches.suse dir from the filepath
                basename = PurePath(patch).name.replace(".patch", "")

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
                            self.kern_src,
                            "log",
                            "--no-merges",
                            "--pretty=oneline",
                            f"remotes/origin/{mbranch}",
                            "--",
                            patch,
                        ],
                        stderr=subprocess.STDOUT,
                    ).decode("ISO-8859-1")
                except subprocess.CalledProcessError:
                    print(
                        f"File {fname} doesn't exists {mbranch}. It could "
                        " be removed, so the branch is not affected by the issue."
                    )
                    commits[bc]["commits"] = ["Not affected"]
                    continue

                # Skip the Update commits, that only change the References tag
                for hash_entry in phashes.splitlines():
                    if "Update" in hash_entry and "patches.suse" in hash_entry:
                        continue

                    # Sometimes we can have a commit that touches two files. In
                    # these cases we can have duplicated hash commits, since git
                    # history for each individual file will show the same hash.
                    # Skip if the same hash already exists.
                    hash_commit = hash_entry.split(" ")[0]
                    if hash_commit not in commits[bc]["commits"]:
                        commits[bc]["commits"].append(hash_commit)

        # Grab each commits subject and date for each commit. The commit dates
        # will be used to sort the patches in the order they were
        # created/merged.
        ucommits_sort = []
        for c in ucommits:
            d, msg = GitHelper.get_commit_data(c, upatches)
            ucommits_sort.append((d, c, msg))

        ucommits_sort.sort()
        commits["upstream"] = {"commits": []}
        for d, c, msg in ucommits_sort:
            commits["upstream"]["commits"].append(f'{c} ("{msg}")')

        print("")

        for key, val in commits.items():
            print(f"{key}")
            branch_commits = val["commits"]
            if not branch_commits:
                print("None")
            for c in branch_commits:
                print(c)
            print("")

        return commits

    def get_patched_kernels(self, commits):
        if not commits:
            return []

        if not self.kern_src:
            logging.info("KLP_KERNEL_SOURCE not defined, skip getting SUSE commits")
            return []

        print("Searching for already patched codestreams...")

        patched = []
        for bc, _ in self.kernel_branches.items():
            suse_commits = commits[bc]["commits"]
            if not suse_commits:
                continue

            tag_commits = {}

            # Grab only the first commit, since they would be put together
            # in a release either way. The order of the array is backards, the
            # first entry will be the last patch found.
            for su in suse_commits:
                tag_commits[su] = []

                tags = subprocess.check_output(["/usr/bin/git", "-C", self.kern_src, "tag",
                                                f"--contains={su}",
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
            total_commits = len(suse_commits)
            for tag, b in tag_commits.items():
                if len(b) == total_commits:
                    patched.append(tag)

        # remove duplicates
        return natsorted(list(set(patched)))
