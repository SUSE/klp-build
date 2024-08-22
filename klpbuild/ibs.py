# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import concurrent.futures
import errno
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from operator import itemgetter
from pathlib import Path
import pkg_resources

import requests
from lxml import etree
from lxml.objectify import fromstring
from lxml.objectify import SubElement
from natsort import natsorted
from osctiny import Osc

from klpbuild.config import Config
from klpbuild.ksrc import GitHelper
from klpbuild.utils import ARCH
from klpbuild.utils import ARCHS


class IBS(Config):
    def __init__(self, lp_name, lp_filter, working_cs={}):
        super().__init__(lp_name, lp_filter, working_cs=working_cs)
        self.osc = Osc(url="https://api.suse.de")

        self.ibs_user = self.osc.username
        self.prj_prefix = f"home:{self.ibs_user}:{self.lp_name}-klp"

        self.ksrc = GitHelper(self.lp_name, self.filter, None)

        # Total number of work items
        self.total = 0

        # Skip osctiny INFO messages
        logging.getLogger("osctiny").setLevel(logging.WARNING)

    def do_work(self, func, args):
        if len(args) == 0:
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
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

            if self.filter and not re.match(self.filter, cs):
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

        path_dest = self.get_data_dir(arch)
        path_dest.mkdir(exist_ok=True, parents=True)

        rpm_file = Path(dest, rpm)
        cmd = f"rpm2cpio {rpm_file} | cpio --quiet -uidm"
        subprocess.check_output(cmd, shell=True, cwd=path_dest)

        logging.info(f"({i}/{self.total}) extracted {cs} {rpm}: ok")

    def download_and_extract(self, args):
        i, cs, prj, repo, arch, pkg, rpm, dest = args

        self.download_binary_rpms(args)

        # Do not extract kernel-macros rpm
        if "kernel-macros" not in rpm:
            self.extract_rpms((i, cs, arch, rpm, dest))

    def download_cs_data(self, cs_list):
        rpms = []
        i = 1

        cs_data = {
            "kernel-default": r"(kernel-(default|rt)\-((livepatch|kgraft)?\-?devel)?\-?[\d\.\-]+.(s390x|x86_64|ppc64le).rpm)",
            "kernel-source": r"(kernel-(source|devel)(\-rt)?\-?[\d\.\-]+.noarch.rpm)",
        }

        logging.info("Getting list of files...")
        for cs, data in cs_list.items():
            prj = data["project"]
            repo = data["repo"]

            path_dest = Path(self.data, "kernel-rpms")
            path_dest.mkdir(exist_ok=True, parents=True)

            for arch in self.get_cs_archs(cs):
                for pkg, regex in cs_data.items():
                    # RT kernels have different package names
                    if self.cs_is_rt(cs):
                        if pkg == "kernel-default":
                            pkg = "kernel-rt"
                        elif pkg == "kernel-source":
                            pkg = "kernel-source-rt"

                    if repo != "standard":
                        pkg = f"{pkg}.{repo}"

                    ret = self.osc.build.get_binary_list(prj, repo, arch, pkg)
                    for file in re.findall(regex, str(etree.tostring(ret))):
                        # FIXME: adjust the regex to only deal with strings
                        if isinstance(file, str):
                            rpm = file
                        else:
                            rpm = file[0]

                        # Download all packages for the HOST arch
                        # For the others only download kernel-default
                        if arch != ARCH and not re.search("kernel-default-\d", rpm):
                            continue

                        # Extract the source and kernel-devel in the current
                        # machine arch to make it possible to run klp-build in
                        # different architectures
                        if "kernel-source" in rpm or "kernel-default-devel" in rpm:
                            if arch != ARCH:
                                continue

                        rpms.append((i, cs, prj, repo, arch, pkg, rpm, path_dest))
                        i += 1

        logging.info(f"Downloading {len(rpms)} rpms...")
        self.total = len(rpms)
        self.do_work(self.download_and_extract, rpms)

        # Create a list of paths pointing to lib/modules for each downloaded
        # codestream
        for cs, data in cs_list.items():
            for arch in self.get_cs_archs(cs):
                kname = data["kernel"] + "-default"
                if data.get("rt", ""):
                    kname = data['kernel'] + "-rt"

                # Extract modules and vmlinux files that are compressed
                mod_path = Path(self.get_data_dir(arch), "lib", "modules", kname)
                for fext, ecmd in [("zst", "unzstd -f -d"), ("xz", "xz --quiet -d -k")]:
                    cmd = rf'find {mod_path} -name "*ko.{fext}" -exec {ecmd} --quiet {{}} \;'
                    subprocess.check_output(cmd, shell=True)

                # Extract gzipped vmlinux per arch
                vmlinux_path = Path(self.get_data_dir(arch), "boot", f"vmlinux-{kname}.gz")
                # ppc64le doesn't gzips vmlinux
                if vmlinux_path.exists():
                    subprocess.check_output(rf'gzip -k -d -f {vmlinux_path}', shell=True)

            # Use the SLE .config
            shutil.copy(self.get_cs_kernel_config(cs, ARCH), Path(self.get_odir(cs), ".config"))

            # Recreate the build link to enable us to test the generated LP
            mod_path = Path(self.get_mod_path(cs, ARCH), "build")
            mod_path.unlink()
            os.symlink(self.get_odir(cs), mod_path)

        logging.info("Finished extract vmlinux and modules...")

    def download_binary_rpms(self, args):
        i, cs, prj, repo, arch, pkg, rpm, dest = args

        try:
            self.osc.build.download_binary(prj, repo, arch, pkg, rpm, dest)
            logging.info(f"({i}/{self.total}) {cs} {rpm}: ok")
        except OSError as e:
            if e.errno == errno.EEXIST:
                logging.info(f"({i}/{self.total}) {cs} {rpm}: already downloaded. skipping.")
            else:
                raise RuntimeError(f"download error on {prj}: {rpm}")

    def convert_prj_to_cs(self, prj):
        return prj.replace(f"{self.prj_prefix}-", "").replace("_", ".")

    def apply_filter(self, item_list):
        if not self.filter:
            return item_list

        filtered = []
        for item in item_list:
            cmp_item = self.convert_prj_to_cs(item)
            if not re.match(self.filter, cmp_item):
                continue

            filtered.append(item)

        return filtered

    def find_missing_symbols(self, cs, arch, lp_mod_path):
        vmlinux_path = self.get_cs_boot_file(cs, "vmlinux", arch)
        vmlinux_syms = self.get_all_symbols_from_object(vmlinux_path, True)

        # Get list of UNDEFINED symbols from the livepatch module
        lp_und_symbols = self.get_all_symbols_from_object(lp_mod_path, False)

        missing_syms = []
        # Find all UNDEFINED symbols that exists in the livepatch module that
        # aren't defined in the vmlinux
        for sym in lp_und_symbols:
            if sym not in vmlinux_syms:
                missing_syms.append(sym)

        return missing_syms

    def validate_livepatch_module(self, cs, arch, rpm_dir, rpm):
        match = re.search(r"(livepatch)-.*(default|rt)\-(\d+)\-(\d+)\.(\d+)\.(\d+)\.", rpm)
        if match:
            dir_path = match.group(1)
            ktype = match.group(2)
            lp_file = f"livepatch-{match.group(3)}-{match.group(4)}_{match.group(5)}_{match.group(6)}.ko"
        else:
            ktype = "default"
            match = re.search(r"(kgraft)\-patch\-.*default\-(\d+)\-(\d+)\.(\d+)\.", rpm)
            if match:
                dir_path = match.group(1)
                lp_file = f"kgraft-patch-{match.group(2)}-{match.group(3)}_{match.group(4)}.ko"

        fdest = Path(rpm_dir, rpm)
        # Extract the livepatch module for later inspection
        cmd = f"rpm2cpio {fdest} | cpio --quiet -uidm"
        subprocess.check_output(cmd, shell=True, cwd=rpm_dir)

        # Check depends field
        # At this point we found that our livepatch module depends on
        # exported functions from other modules. List the modules here.
        lp_mod_path = Path(rpm_dir, "lib", "modules", f"{self.get_cs_kernel(cs)}-{ktype}", dir_path, lp_file)
        elffile = self.get_elf_object(lp_mod_path)
        deps = self.get_elf_modinfo_entry(elffile, "depends")
        if len(deps):
            logging.warning(f"{cs}:{arch} has dependencies: {deps}.")

        funcs = self.find_missing_symbols(cs, arch, lp_mod_path)
        if funcs:
            logging.warning(f'{cs}:{arch} Undefined functions: {" ".join(funcs)}')

        shutil.rmtree(Path(rpm_dir, "lib"), ignore_errors=True)

    # Parse 15.2u25 to SLE15-SP2_Update_25
    def get_full_cs(self, cs):
        sle, sp, up, rt = self.get_cs_tuple(cs)

        buf = f"SLE{sle}"

        if int(sp) > 0:
            buf = f"{buf}-SP{sp}"

        if rt:
            buf = f"{buf}-RT"

        return f"{buf}_Update_{up}"

    def prepare_tests(self):
        # Download all built rpms
        self.download()

        test_src = self.get_tests_path()
        run_test = pkg_resources.resource_filename("scripts", "run-kgr-test.sh")

        for arch in ARCHS:
            tests_path = Path(self.lp_path, "tests", arch)
            test_arch_path = Path(tests_path, self.lp_name)

            # Remove previously created directory and archive
            shutil.rmtree(test_arch_path, ignore_errors=True)
            shutil.rmtree(f"{str(test_arch_path)}.tar.xz", ignore_errors=True)

            test_arch_path.mkdir(exist_ok=True, parents=True)
            shutil.copy(run_test, test_arch_path)

            for d in ["built", "repro", "tests.out"]:
                Path(test_arch_path, d).mkdir(exist_ok=True)

            build_cs = []
            for cs, data in self.filter_cs(verbose=False).items():
                if arch not in data["archs"]:
                    continue

                rpm_dir = Path(self.lp_path, "ccp", cs, arch, "rpm")
                if not rpm_dir.exists():
                    logging.info(f"{cs}/{arch}: rpm dir not found. Skipping.")
                    continue

                # TODO: there will be only one rpm, format it directly
                rpm = os.listdir(rpm_dir)
                if len(rpm) > 1:
                    raise RuntimeError(f"ERROR: {cs}/{arch}. {len(rpm)} rpms found. Excepting to find only one")

                for rpm in os.listdir(rpm_dir):
                    # Check for dependencies
                    self.validate_livepatch_module(cs, arch, rpm_dir, rpm)

                    shutil.copy(Path(rpm_dir, rpm), Path(test_arch_path, "built"))

                if "rt" in cs and arch != "x86_64":
                    continue

                build_cs.append(self.get_full_cs(cs))

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

            subprocess.run(
                ["tar", "-cJf", f"{self.lp_name}.tar.xz", f"{self.lp_name}"],
                cwd=tests_path,
                stdout=sys.stdout,
                stderr=subprocess.PIPE,
                check=True,
            )

    # We can try delete a project that was removed, so don't bother with errors
    def delete_rpms(self, cs):
        try:
            for arch in self.get_cs_archs(cs):
                shutil.rmtree(Path(self.lp_path, "ccp", cs, arch, "rpm"), ignore_errors=True)
        except KeyError:
            pass

    def download(self):
        rpms = []
        i = 1
        for result in self.get_projects():
            prj = result.get("name")
            cs = self.convert_prj_to_cs(prj)

            # Remove previously downloaded rpms
            self.delete_rpms(cs)

            archs = result.xpath("repository/arch")
            for arch in archs:
                ret = self.osc.build.get_binary_list(prj, "devbuild", arch, "klp")
                rpm_name = f"{arch}.rpm"
                for rpm in ret.xpath("binary/@filename"):
                    if not rpm.endswith(rpm_name):
                        continue

                    if "preempt" in rpm:
                        continue

                    # Create a directory for each arch supported
                    dest = Path(self.lp_path, "ccp", cs, str(arch), "rpm")
                    dest.mkdir(exist_ok=True, parents=True)

                    rpms.append((i, prj, prj, "devbuild", arch, "klp", rpm, dest))
                    i += 1

        logging.info(f"Downloading {len(rpms)} packages")
        self.total = len(rpms)
        self.do_work(self.download_binary_rpms, rpms)

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
                    if len(states) == 1 and states.pop() == "succeeded":
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
        return self.prj_prefix + "-" + cs.replace(".", "_")

    def create_prj_meta(self, cs):
        data = self.get_cs_data(cs)

        prj = fromstring(
            "<project name=''><title></title><description></description>"
            "<build><enable/></build><publish><disable/></publish>"
            "<debuginfo><disable/></debuginfo>"
            '<repository name="devbuild">'
            f"<path project=\"{data['project']}\" repository=\"{data['repo']}\"/>"
            "</repository>"
            "</project>"
        )

        repo = prj.find("repository")

        for arch in self.get_cs_archs(cs):
            ar = SubElement(repo, "arch")
            ar._setText(arch)

        return prj

    def create_lp_package(self, i, cs):
        # get the kgraft branch related to this codestream
        branch = self.ksrc.get_cs_branch(cs)
        if not branch:
            logging.info(f"Could not find git branch for {cs}. Skipping.")
            return

        logging.info(f"({i}/{self.total}) pushing {cs} using branch {branch}...")

        # If the project exists, drop it first
        prj = self.cs_to_project(cs)
        self.delete_project(i, prj, verbose=False)

        meta = self.create_prj_meta(cs)
        prj_desc = f"Development of livepatches for {cs}"

        try:
            self.osc.projects.set_meta(
                prj, metafile=meta, title="", bugowner=self.ibs_user, maintainer=self.ibs_user, description=prj_desc
            )

            self.osc.packages.set_meta(prj, "klp", title="", description="Test livepatch")

        except Exception as e:
            logging.error(e, e.response.content)
            raise RuntimeError("")

        base_path = Path(self.lp_path, "ccp", cs)

        # Remove previously created directories
        prj_path = Path(base_path, "checkout")
        if prj_path.exists():
            shutil.rmtree(prj_path)

        code_path = Path(base_path, "code")
        if code_path.exists():
            shutil.rmtree(code_path)

        self.osc.packages.checkout(prj, "klp", prj_path)

        kgraft_path = self.get_user_path('kgr_patches_dir')

        # Get the code from codestream
        subprocess.check_output(
            ["/usr/bin/git", "clone", "--single-branch", "-b", branch, str(kgraft_path), str(code_path)],
            stderr=subprocess.STDOUT,
        )

        # Check if the directory related to this bsc exists.
        # Otherwise only warn the caller about this fact.
        # This scenario can occur in case of LPing function that is already
        # part of different LP in which case we modify the existing one.
        if self.lp_name not in os.listdir(code_path):
            logging.warning(f"Warning: Directory {self.lp_name} not found on branch {branch}")

        # Fix RELEASE version
        with open(Path(code_path, "scripts", "release-version.sh"), "w") as f:
            ver = self.get_full_cs(cs).replace("EMBARGO", "")
            f.write(f"RELEASE={ver}")

        subprocess.check_output(
            ["bash", "./scripts/tar-up.sh", "-d", str(prj_path)], stderr=subprocess.STDOUT, cwd=code_path
        )
        shutil.rmtree(code_path)

        # Add all files to the project, commit the changes and delete the directory.
        for fname in prj_path.iterdir():
            with open(fname, "rb") as fdata:
                self.osc.packages.push_file(prj, "klp", fname.name, fdata.read())
        self.osc.packages.cmd(prj, "klp", "commit", comment=f"Dump {branch}")
        shutil.rmtree(prj_path)

        logging.info(f"({i}/{self.total}) {cs} done")

    def log(self, cs, arch):
        logging.info(self.osc.build.get_log(self.cs_to_project(cs), "devbuild", arch, "klp"))

    def push(self, wait=False):
        cs_list = self.apply_filter(self.codestreams.keys())

        if not cs_list:
            logging.error(f"push: No codestreams found for {self.lp_name}")
            sys.exit(1)

        logging.info(f"Preparing {len(cs_list)} projects on IBS...")

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
