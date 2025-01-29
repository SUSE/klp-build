# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from pathlib import PurePath

import requests
from natsort import natsorted

from klpbuild.klplib import utils
from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.ibs import IBS
from klpbuild.klplib.supported import get_supported_codestreams


class GitHelper():
    def __init__(self, lp_filter):

        self.kern_src = get_user_path('kernel_src_dir', isopt=True)

        self.kernel_branches = {
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
        }

        self.lp_filter = lp_filter

    def format_patches(self, lp_name, version):
        ver = f"v{version}"
        # index 1 will be the test file
        index = 2

        kgr_patches = get_user_path('kgr_patches_dir')
        if not kgr_patches:
            logging.warning("kgr_patches_dir not found, patches will be incomplete")

        # Remove dir to avoid leftover patches with different names
        patches_dir = utils.get_workdir(lp_name)/"patches"
        shutil.rmtree(patches_dir, ignore_errors=True)

        test_src = utils.get_tests_path(lp_name)
        subprocess.check_output(
            [
                "/usr/bin/git",
                "-C",
                str(get_user_path('kgr_patches_tests_dir')),
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
        for branch in utils.get_lp_branches(lp_name, kgr_patches):
            print(branch)
            bname = branch.replace(lp_name + "_", "")
            bs = " ".join(bname.split("_"))
            bsc = lp_name.replace("bsc", "bsc#")

            prefix = f"PATCH {ver} {bsc} {bs}"

            subprocess.check_output(
                [
                    "/usr/bin/git",
                    "-C",
                    str(kgr_patches),
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
    @staticmethod
    def get_commit_data(commit, savedir=None):
        req = requests.get(
            f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit}", timeout=15)
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


    def get_commits(self, lp_name, cve):
        if not self.kern_src:
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

        print("Fetching changes from all supported branches...")

        # Mount the command to fetch all branches for supported codestreams
        subprocess.check_output(["/usr/bin/git", "-C", str(self.kern_src), "fetch",
                                 "--quiet", "--atomic", "--force", "--tags", "origin"] +
                                list(self.kernel_branches.values()))

        print("Getting SUSE fixes for upstream commits per CVE branch. It can take some time...")

        # Store all commits from each branch and upstream
        commits = {}
        # List of upstream commits, in creation date order
        ucommits = []

        upatches = utils.get_workdir(lp_name)/"upstream"
        upatches.mkdir(exist_ok=True, parents=True)

        # Get backported commits from all possible branches, in order to get
        # different versions of the same backport done in the CVE branches.
        # Since the CVE branch can be some patches "behind" the LTSS branch,
        # it's good to have both backports code at hand by the livepatch author
        for bc, mbranch in self.kernel_branches.items():
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
                if patch.strip().startswith("#"):
                    continue

                idx += 1
                branch_path = utils.get_workdir(lp_name)/"fixes"/bc
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
                            "--numstat",
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

                iphashes = iter(phashes.splitlines())
                for hash_entry in iphashes:
                    stats = next(iphashes)

                    # Skip the Update commits, that only change the References tag
                    if "Update" in hash_entry and "patches.suse" in hash_entry:
                        continue

                    # Skip commits that change one single line. Most likely just a
                    # reference update.
                    if stats.split()[0] is "1":
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

    def get_patched_tags(self, suse_commits):
        tag_commits = {}
        patched = []
        total_commits = len(suse_commits)

        # Grab only the first commit, since they would be put together
        # in a release either way. The order of the array is backards, the
        # first entry will be the last patch found.
        for su in suse_commits:
            tag_commits[su] = []

            tags = subprocess.check_output(["/usr/bin/git", "-C", self.kern_src,
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

        ret = subprocess.check_output(["/usr/bin/git", "-C", self.kern_src, "log",
                                       f"--grep=CVE-{cve}",
                                       f"--tags=*rpm-{kernel}",
                                       "--pretty=oneline"])

        for line in ret.decode().splitlines():
            # Skip the Update commits, that only change the References tag
            if "Update" in line and "patches.suse" in line:
                continue

            # Parse commit's hash
            commits.append(line.split()[0])

        # "patched kernels" are those which contain all commits.
        return len(suse_commits) == len(commits), commits

    def get_patched_kernels(self, codestreams, commits, cve):
        if not commits:
            return []

        if not self.kern_src:
            logging.info("kernel_src_dir not found, skip getting SUSE commits")
            return []

        if not cve:
            logging.info("No CVE informed, skipping the processing of getting the patched kernels.")
            return []

        print("Searching for already patched codestreams...")

        kernels = []

        for bc, _ in self.kernel_branches.items():
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

                print(f"\n{cs.name()} ({kernel}):")

                # If no patches/commits were found for this kernel, fallback to
                # the commits in the main SLE branch. In either case, we can
                # assume that this kernel is already patched.
                for c in kern_commits if patched else suse_commits:
                    print(f"{c}")

                kernels.append(kernel)

        print("")

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


    def scan(self, lp_name, cve, conf, no_check):
        # Always get the latest supported.csv file and check the content
        # against the codestreams informed by the user
        all_codestreams = get_supported_codestreams()

        if not cve or no_check:
            commits = {}
            patched_kernels = []
        else:
            commits = self.get_commits(lp_name, cve)
            patched_kernels = self.get_patched_kernels(all_codestreams, commits, cve)

        # list of codestreams that matches the file-funcs argument
        working_cs = []
        patched_cs = []
        unaffected_cs = []
        data_missing = []
        cs_missing = []
        conf_not_set = []

        if no_check:
            logging.info("Option --no-check was specified, checking all codestreams that are not filtered out...")

        for cs in all_codestreams:
            # Skip patched codestreams
            if not no_check:
                if cs.kernel in patched_kernels:
                    patched_cs.append(cs.name())
                    continue

                if not GitHelper.cs_is_affected(cs, cve, commits):
                    unaffected_cs.append(cs)
                    continue

            cs.set_archs()

            if conf and not cs.get_boot_file("config").exists():
                data_missing.append(cs)
                cs_missing.append(cs.name())
                # recheck later if we can add the missing codestreams
                continue

            if conf and not cs.get_all_configs(conf):
                conf_not_set.append(cs)
                continue

            working_cs.append(cs)

        # Found missing cs data, downloading and extract
        if data_missing:
            logging.info("Download the necessary data from the following codestreams:")
            logging.info("\t%s\n", " ".join(cs_missing))
            IBS(lp_name, self.lp_filter).download_cs_data(data_missing)
            logging.info("Done.")

            for cs in data_missing:
                # Ok, the downloaded codestream has the configuration set
                if cs.get_all_configs(conf):
                    working_cs.append(cs)
                # Nope, the config is missing, so don't add it to working_cs
                else:
                    conf_not_set.append(cs)

        if conf_not_set:
            cs_list = utils.classify_codestreams(conf_not_set)
            logging.info("Skipping codestreams without %s set:", conf)
            logging.info("\t%s", " ".join(cs_list))

        if patched_cs:
            cs_list = utils.classify_codestreams(patched_cs)
            logging.info("Skipping already patched codestreams:")
            logging.info("\t%s", " ".join(cs_list))

        if unaffected_cs:
            cs_list = utils.classify_codestreams(unaffected_cs)
            logging.info("Skipping unaffected codestreams (missing backports):")
            logging.info("\t%s", " " .join(cs_list))

        # working_cs will contain the final dict of codestreams that wast set
        # by the user, avoid downloading missing codestreams that are not affected
        working_cs = utils.filter_codestreams(self.lp_filter, working_cs, verbose=True)

        if not working_cs:
            logging.info("All supported codestreams are already patched. Exiting klp-build")
            sys.exit(0)

        logging.info("All affected codestreams:")
        cs_list = utils.classify_codestreams(working_cs)
        logging.info("\t%s", " ".join(cs_list))

        return commits, patched_cs, patched_kernels, working_cs
