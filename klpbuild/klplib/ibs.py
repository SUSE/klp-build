# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import concurrent.futures
import errno
import importlib
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from operator import itemgetter
from pathlib import Path

import requests
from lxml import etree
from lxml.objectify import fromstring
from lxml.objectify import SubElement
from natsort import natsorted
from osctiny import Osc

from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib.codestreams_data import get_codestream_by_name, get_codestreams_dict, get_codestreams_items
from klpbuild.klplib.config import get_user_path, get_user_settings
from klpbuild.klplib.utils import ARCH, ARCHS, get_all_symbols_from_object, get_datadir, get_elf_object, get_cs_branch, get_kgraft_branch, filter_codestreams, get_workdir,  get_tests_path, classify_codestreams_str


class IBS():
    def __init__(self, lp_name, lp_filter):
        self.osc = Osc(url="https://api.suse.de")

        self.lp_name = lp_name
        self.lp_filter = lp_filter

        self.ibs_user = self.osc.username
        self.prj_prefix = f"home:{self.ibs_user}:{self.lp_name}-klp"

        self.workers = int(get_user_settings("workers"))

        # Total number of work items
        self.total = 0

        # Skip osctiny INFO messages
        logging.getLogger("osctiny").setLevel(logging.WARNING)

    def do_work(self, func, args):
        if len(args) == 0:
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            results = executor.map(func, args)
            for result in results:
                if result:
                    logging.error(result)

    # The projects has different format: 12_5u5 instead of 12.5u5
    def get_projects(self):
        prjs = []
        projects = self.osc.search.project(f"starts-with(@name, '{self.prj_prefix}')")

        for prj in projects.findall("project"):
            prj_name = prj.get("name")
            cs = self.convert_prj_to_cs(prj_name)

            if self.lp_filter and not re.match(self.lp_filter, cs):
                continue

            prjs.append(prj)

        return prjs

    def get_project_names(self):
        names = []
        i = 1
        for result in self.get_projects():
            names.append((i, result.get("name")))
            i += 1

        return natsorted(names, key=itemgetter(1))

    def delete_project(self, i, prj, verbose=True):
        try:
            ret = self.osc.projects.delete(prj, force=True)
            if type(ret) is not bool:
                logging.error(etree.tostring(ret))
                raise ValueError(prj)
        except requests.exceptions.HTTPError as e:
            # project not found, no problem
            if e.response.status_code == 404:
                pass

        if verbose:
            logging.info(f"({i}/{self.total}) {prj} deleted")

    def delete_projects(self, prjs, verbose=True):
        for i, prj in prjs:
            self.delete_project(i, prj, verbose)

    def extract_rpms(self, args):
        i, cs, arch, rpm, dest = args

        # We don't need to extract the -extra packages for non x86_64 archs.
        # These packages are only needed to be uploaded to the kgr-test
        # repos, since they aren't published, but we need them for testing.
        if arch != "x86_64" and "-extra" in rpm:
            return

        path_dest = get_datadir(arch)
        path_dest.mkdir(exist_ok=True, parents=True)

        rpm_file = Path(dest, rpm)
        cmd = f"rpm2cpio {rpm_file} | cpio --quiet -uidm"
        subprocess.check_output(cmd, shell=True, stderr=None, cwd=path_dest)

        logging.info(f"({i}/{self.total}) extracted {cs.name()} {rpm}: ok")

    def download_and_extract(self, args):
        i, cs, _, _, arch, _, rpm, dest = args

        # Try to download and extract at least twice if any problems arise
        tries = 2
        while tries > 0:
            self.download_binary_rpms(args)
            try:
                self.extract_rpms((i, cs, arch, rpm, dest))
                # All good, stop the loop
                break
            except Exception as e:
                # There was an issue when extracting the RPMs, probably because it's broken
                # Remove the downloaded RPMs and try again
                tries = tries - 1
                logging.info(f"Problem to extract {rpm}. Downloading it again")
                Path(dest, rpm).unlink()

        if tries == 0:
            raise RuntimeError(f"Failed to extract {rpm}. Aborting")

    def get_cs_packages(self, cs_list, dest):
        # The packages that we search for are:
        # kernel-source
        # kernel-devel
        # kernel-(default|rt)
        # kernel-(default|rt)-devel
        # kernel-(default|rt)-livepatch-devel (for SLE15+)
        # kernel-default-kgraft (for SLE12)
        # kernel-default-kgraft-devel (for SLE12)
        cs_data = {
            "kernel-default": r"(kernel-(default|rt)\-((livepatch|kgraft)?\-?devel)?\-?[\d\.\-]+.(s390x|x86_64|ppc64le).rpm)",
            "kernel-source": r"(kernel-(source|devel)(\-rt)?\-?[\d\.\-]+.noarch.rpm)",
        }

        rpms = []
        i = 1

        logging.info("Getting list of files...")
        for cs in cs_list:
            for arch in cs.archs:
                for pkg, regex in cs_data.items():
                    if cs.is_micro:
                        # For MICRO, we use the patchid to find the list of binaries
                        pkg = cs.patchid

                    elif cs.rt:
                        # RT kernels have different package names
                        if pkg == "kernel-default":
                            pkg = "kernel-rt"
                        elif pkg == "kernel-source":
                            pkg = "kernel-source-rt"

                    if cs.repo != "standard":
                        pkg = f"{pkg}.{cs.repo}"

                    ret = self.osc.build.get_binary_list(cs.project, cs.repo, arch, pkg)
                    for file in re.findall(regex, str(etree.tostring(ret))):
                        # FIXME: adjust the regex to only deal with strings
                        if isinstance(file, str):
                            rpm = file
                        else:
                            rpm = file[0]

                        # Download all packages for the HOST arch
                        # For the others only download kernel-default
                        if arch != ARCH and not re.search(r"kernel-default-\d", rpm):
                            continue

                        # Extract the source and kernel-devel in the current
                        # machine arch to make it possible to run klp-build in
                        # different architectures
                        if "kernel-source" in rpm or "kernel-default-devel" in rpm:
                            if arch != ARCH:
                                continue

                        rpms.append((i, cs, cs.project, cs.repo, arch, pkg, rpm, dest))
                        i += 1

        return rpms

    def download_cs_data(self, cs_list):
        dest = get_datadir()/"kernel-rpms"
        dest.mkdir(exist_ok=True, parents=True)

        rpms = self.get_cs_packages(cs_list, dest)

        logging.info("Downloading %s rpms...", len(rpms))
        self.total = len(rpms)
        self.do_work(self.download_and_extract, rpms)

        # Create a list of paths pointing to lib/modules for each downloaded
        # codestream
        for cs in cs_list:
            for arch in cs.archs:
                # Extract modules and vmlinux files that are compressed
                mod_path = cs.get_mod_path(arch)
                logging.info("extracting %s:%s in %s", arch, cs.name(), str(mod_path))
                for fext, ecmd in [("zst", "unzstd --rm -f -d"), ("xz", "xz --quiet -d -k")]:
                    cmd = rf'find {mod_path} -name "*.{fext}" -exec {ecmd} --quiet {{}} \;'
                    subprocess.check_output(cmd, shell=True)

                # Extract gzipped files per arch
                files = ["vmlinux", "symvers"]
                for f in files:
                    f_path = cs.get_boot_file(f"{f}.gz", arch)
                    # ppc64le doesn't gzips vmlinux
                    if f_path.exists():
                        logging.info("extracting %s:%s:%s", arch, cs.name(), f)
                        subprocess.check_output(rf'gzip -k -d -f {f_path}', shell=True)

            # Use the SLE .config
            shutil.copy(cs.get_boot_file("config"), Path(cs.get_obj_dir(), ".config"))

            # Recreate the build link to enable us to test the generated LP
            mod_path = cs.get_kernel_build_path(ARCH)
            mod_path.unlink()
            os.symlink(cs.get_obj_dir(), mod_path)

        # Create symlink from lib to usr/lib so we can use virtme on the
        # extracted kernels
        usr_lib = get_datadir()/ARCH/"usr"/"lib"
        if not usr_lib.exists():
            usr_lib.symlink_to(get_datadir()/ARCH/"lib")

        logging.info("Finished extract vmlinux and modules...")

    def download_binary_rpms(self, args):
        i, cs, prj, repo, arch, pkg, rpm, dest = args

        try:
            self.osc.build.download_binary(prj, repo, arch, pkg, rpm, dest)
            logging.info(f"({i}/{self.total}) {cs.name()} {rpm}: ok")
        except OSError as e:
            if e.errno == errno.EEXIST:
                logging.info(f"({i}/{self.total}) {cs.name()} {rpm}: already downloaded. skipping.")
            else:
                raise RuntimeError(f"download error on {prj}: {rpm}") from e

    def convert_prj_to_cs(self, prj):
        return prj.replace(f"{self.prj_prefix}-", "").replace("_", ".")

    def find_missing_symbols(self, cs, arch, lp_mod_path):
        vmlinux_path = cs.get_boot_file("vmlinux", arch)
        vmlinux_syms = get_all_symbols_from_object(vmlinux_path, True)

        # Get list of UNDEFINED symbols from the livepatch module
        lp_und_symbols = get_all_symbols_from_object(lp_mod_path, False)

        missing_syms = []
        # Find all UNDEFINED symbols that exists in the livepatch module that
        # aren't defined in the vmlinux
        for sym in lp_und_symbols:
            if sym not in vmlinux_syms:
                missing_syms.append(sym)

        return missing_syms

    def validate_livepatch_module(self, cs, arch, rpm_dir, rpm):
        fdest = Path(rpm_dir, rpm)
        # Extract the livepatch module for later inspection
        subprocess.check_output(f"rpm2cpio {fdest} | cpio --quiet -uidm",
                                shell=True, cwd=rpm_dir)

        # There should be only one .ko file extracted
        lp_mod_path = sorted(rpm_dir.glob("**/*.ko"))[0]
        elffile = get_elf_object(lp_mod_path)

        funcs = self.find_missing_symbols(cs, arch, lp_mod_path)
        if funcs:
            logging.warning(f'{cs.name()}:{arch} Undefined functions: {" ".join(funcs)}')

        shutil.rmtree(Path(rpm_dir, "lib"), ignore_errors=True)

    def prepare_tests(self):
        # Download all built rpms
        self.download()

        test_src = get_tests_path(self.lp_name)
        run_test = importlib.resources.files("scripts") / "run-kgr-test.sh"

        logging.info(f"Validating the downloaded RPMs...")

        for arch in ARCHS:
            tests_path = get_workdir(self.lp_name)/"tests"/arch
            test_arch_path = Path(tests_path, self.lp_name)

            # Remove previously created directory and archive
            shutil.rmtree(test_arch_path, ignore_errors=True)
            shutil.rmtree(f"{str(test_arch_path)}.tar.xz", ignore_errors=True)

            test_arch_path.mkdir(exist_ok=True, parents=True)
            shutil.copy(run_test, test_arch_path)

            for d in ["built", "repro", "tests.out"]:
                Path(test_arch_path, d).mkdir(exist_ok=True)

            logging.info(f"Checking {arch} symbols...")
            build_cs = []
            for cs in filter_codestreams(self.lp_filter, get_codestreams_dict()):
                if arch not in cs.archs:
                    continue

                rpm_dir = Path(cs.get_ccp_dir(self.lp_name), arch, "rpm")
                if not rpm_dir.exists():
                    logging.info(f"{cs.name()}/{arch}: rpm dir not found. Skipping.")
                    continue

                # TODO: there will be only one rpm, format it directly
                rpm = os.listdir(rpm_dir)
                if len(rpm) > 1:
                    raise RuntimeError(f"ERROR: {cs.name()}/{arch}. {len(rpm)} rpms found. Excepting to find only one")

                for rpm in os.listdir(rpm_dir):
                    # Check for dependencies
                    self.validate_livepatch_module(cs, arch, rpm_dir, rpm)

                    shutil.copy(Path(rpm_dir, rpm), Path(test_arch_path, "built"))

                if cs.rt and arch != "x86_64":
                    continue

                build_cs.append(cs.name_full())

            logging.info("Done.")

            # Prepare the config and test files used by kgr-test
            test_dst = Path(test_arch_path, f"repro/{self.lp_name}")
            if test_src.is_file():
                shutil.copy(test_src, f"{test_dst}_test_script.sh")
                config = f"{test_dst}_config.in"
            else:
                # Alternatively, we create test_dst as a directory containing
                # at least a test_script.sh and a config.in
                shutil.copytree(test_src, test_dst)
                config = Path(test_dst, "config.in")

            with open(config, "w") as f:
                f.write("\n".join(natsorted(build_cs)))

            logging.info(f"Creating {arch} tar file...")
            subprocess.run(
                ["tar", "-cJf", f"{self.lp_name}.tar.xz", f"{self.lp_name}"],
                cwd=tests_path,
                stdout=sys.stdout,
                stderr=subprocess.PIPE,
                check=True,
            )

            logging.info("Done.")

    # We can try delete a project that was removed, so don't bother with errors
    def delete_rpms(self, cs):
        try:
            for arch in cs.archs:
                shutil.rmtree(Path(cs.get_ccp_dir(self.lp_name), arch, "rpm"), ignore_errors=True)
        except KeyError:
            pass

    def download(self):
        rpms = []
        i = 1
        for result in self.get_projects():
            prj = result.get("name")
            cs_name = self.convert_prj_to_cs(prj)

            # Get the codestream from the dict
            cs = get_codestream_by_name(cs_name)
            if not cs:
                logging.info(f"Codestream {cs_name} is stale. Deleting it.")
                self.delete_project(0, prj, False)
                continue

            # Remove previously downloaded rpms
            self.delete_rpms(cs)

            archs = result.xpath("repository/arch")
            for arch in archs:
                ret = self.osc.build.get_binary_list(prj, "standard", arch, "klp")
                rpm_name = f"{arch}.rpm"
                for rpm in ret.xpath("binary/@filename"):
                    if not rpm.endswith(rpm_name):
                        continue

                    if "preempt" in rpm:
                        continue

                    # Create a directory for each arch supported
                    dest = Path(cs.get_ccp_dir(self.lp_name), str(arch), "rpm")
                    dest.mkdir(exist_ok=True, parents=True)

                    rpms.append((i, cs, prj, "standard", arch, "klp", rpm, dest))
                    i += 1

        logging.info(f"Downloading {len(rpms)} packages...")
        self.total = len(rpms)
        self.do_work(self.download_binary_rpms, rpms)

        logging.info(f"Download finished.")

    def status(self, wait=False):
        finished_prj = []
        while True:
            prjs = {}
            for _, prj in self.get_project_names():
                if prj in finished_prj:
                    continue

                prjs[prj] = {}

                for res in self.osc.build.get(prj).findall("result"):
                    if not res.xpath("status/@code"):
                        continue
                    code = res.xpath("status/@code")[0]
                    prjs[prj][res.get("arch")] = code

            print(f"{len(prjs)} codestreams to finish")

            for prj, archs in prjs.items():
                st = []
                finished = False
                # Save the status of all architecture build, and set to fail if
                # an error happens in any of the supported architectures
                for k, v in archs.items():
                    st.append(f"{k}: {v}")
                    if v in ["unresolvable", "failed"]:
                        finished = True

                # Only set finished is all architectures supported by the
                # codestreams built without issues
                if not finished:
                    states = set(archs.values())
                    if len(states) == 1 and states.pop() in ["succeeded", "excluded"]:
                        finished = True

                if finished:
                    finished_prj.append(prj)

                logging.info("{}\t{}".format(prj, "\t".join(st)))

            for p in finished_prj:
                prjs.pop(p, None)

            if not wait or not prjs:
                break

            # Wait 30 seconds before getting status again
            time.sleep(30)
            logging.info("")

    def cleanup(self):
        prjs = self.get_project_names()

        self.total = len(prjs)
        if self.total == 0:
            logging.info("No projects found.")
            return

        logging.info(f"Deleting {self.total} projects...")

        self.delete_projects(prjs, True)

    def cs_to_project(self, cs):
        return self.prj_prefix + "-" + cs.name().replace(".", "_")

    def create_prj_meta(self, cs):
        prj = fromstring(
            "<project name=''><title></title><description></description>"
            "<build><enable/></build><publish><disable/></publish>"
            "<debuginfo><disable/></debuginfo>"
            '<repository name="standard">'
            f"<path project=\"{cs.project}\" repository=\"{cs.repo}\"/>"
            "</repository>"
            "</project>"
        )

        repo = prj.find("repository")

        for arch in cs.archs:
            ar = SubElement(repo, "arch")
            ar._setText(arch)

        return prj

    def create_lp_package(self, i, cs):
        kgr_path = get_user_path('kgr_patches_dir')
        branch = get_cs_branch(cs, self.lp_name, kgr_path)
        if not branch:
            logging.info(f"Could not find git branch for {cs.name()}. Skipping.")
            return


        # If the project exists, drop it first
        prj = self.cs_to_project(cs)
        self.delete_project(i, prj, verbose=False)

        meta = self.create_prj_meta(cs)
        prj_desc = f"Development of livepatches for {cs.name()}"

        try:
            self.osc.projects.set_meta(
                prj, metafile=meta, title="", bugowner=self.ibs_user, maintainer=self.ibs_user, description=prj_desc
            )

            self.osc.packages.set_meta(prj, "klp", title="", description="Test livepatch")

        except Exception as e:
            logging.error(e, e.response.content)
            raise RuntimeError("") from e

        # Remove previously created directories
        prj_path = Path(cs.get_ccp_dir(self.lp_name), "checkout")
        if prj_path.exists():
            shutil.rmtree(prj_path)

        code_path = Path(cs.get_ccp_dir(self.lp_name), "code")
        if code_path.exists():
            shutil.rmtree(code_path)

        self.osc.packages.checkout(prj, "klp", prj_path)

        base_branch = get_kgraft_branch(cs.name())

        logging.info("(%s/%s) pushing %s using branches %s/%s...",
                     i, self.total, cs.name(), str(base_branch), str(branch))

        # Clone the repo and checkout to the codestream branch. The branch should be based on master to avoid rebasing
        # conflicts
        subprocess.check_output(
            ["/usr/bin/git", "clone", "--branch", branch, str(kgr_path), str(code_path)],
            stderr=subprocess.STDOUT,
        )

        # Add remote with all codestreams, because the clone above will set the remote origin
        # to the local directory, so it can't find the remote codestreams
        subprocess.check_output(["/usr/bin/git", "remote", "add", "kgr",
                                "gitlab@gitlab.suse.de:kernel/kgraft-patches.git"],
                                stderr=subprocess.STDOUT, cwd=code_path)

        # Fetch all remote codestreams so we can rebase in the next step
        subprocess.check_output(["/usr/bin/git", "fetch", "kgr",  str(base_branch)],
                                stderr=subprocess.STDOUT, cwd=code_path)

        # Get the new bsc commit on top of the codestream branch (should be the last commit on the specific branch)
        subprocess.check_output(
            ["/usr/bin/git", "rebase", f"kgr/{base_branch}"],
            stderr=subprocess.STDOUT, cwd=code_path
        )

        # Check if the directory related to this bsc exists.
        # Otherwise only warn the caller about this fact.
        # This scenario can occur in case of LPing function that is already
        # part of different LP in which case we modify the existing one.
        if self.lp_name not in os.listdir(code_path):
            logging.warning(f"Warning: Directory {self.lp_name} not found on branch {branch}")

        # Fix RELEASE version
        with open(Path(code_path, "scripts", "release-version.sh"), "w") as f:
            ver = cs.name_full().replace("EMBARGO", "")
            f.write(f"RELEASE={ver}")

        subprocess.check_output(
            ["bash", "./scripts/tar-up.sh", "-d", str(prj_path)], stderr=subprocess.STDOUT, cwd=code_path
        )
        shutil.rmtree(code_path)

        # Add all files to the project, commit the changes and delete the directory.
        for fname in prj_path.iterdir():
            # Do not push .osc directory
            if ".osc" in str(fname):
                continue
            with open(fname, "rb") as fdata:
                self.osc.packages.push_file(prj, "klp", fname.name, fdata.read())
        self.osc.packages.cmd(prj, "klp", "commit", comment=f"Dump {branch}")
        shutil.rmtree(prj_path)

        logging.info(f"({i}/{self.total}) {cs.name()} done")

    def log(self, arch):
        cs_list = filter_codestreams(self.lp_filter, get_codestreams_dict())

        if not cs_list:
            logging.error("log: No codestreams found for filter %s", self.lp_filter)
            sys.exit(1)

        if len(cs_list) > 1:
            cs_names = [cs.name() for cs in cs_list]
            logging.error("Filter '%s' returned %d entries (%s), while expecting just one. Aborting. ",
                          self.lp_filter, len(cs_list), " ".join(cs_names))
            sys.exit(1)

        logging.info(self.osc.build.get_log(self.cs_to_project(cs_list[0]), "standard", arch, "klp"))

    def push(self, wait=False):
        cs_list = filter_codestreams(self.lp_filter, get_codestreams_dict())

        if not cs_list:
            logging.error(f"push: No codestreams found for {self.lp_name}")
            sys.exit(1)

        logging.info("Pushing %d codestreams: %s", len(cs_list),
                     classify_codestreams_str(cs_list))

        self.total = len(cs_list)
        i = 1
        # More threads makes OBS to return error 500
        for cs in cs_list:
            self.create_lp_package(i, cs)
            i += 1

        if wait:
            # Give some time for IBS to start building the last pushed
            # codestreams
            time.sleep(30)
            self.status(wait)

            # One more status after everything finished, since we remove
            # finished builds on each iteration
            self.status(False)
