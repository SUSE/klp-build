# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import concurrent.futures
import errno
from itertools import repeat
import logging
import os
import re
import shutil
import subprocess
from operator import itemgetter
from pathlib import Path

import requests
from lxml import etree
from natsort import natsorted
from osctiny import Osc

from klpbuild.klplib.config import get_user_settings
from klpbuild.klplib.utils import ARCH, get_all_symbols_from_object, get_datadir

logging.getLogger("osctiny").setLevel(logging.WARNING)


def convert_prj_to_cs(prj, prefix):
    return prj.replace(f"{prefix}-", "").replace("_", ".")


def convert_cs_to_prj(cs, prefix):
    return prefix + "-" + cs.full_cs_name().replace(".", "_")


def do_work(func, args):
    if len(args) == 0:
        return

    workers = int(get_user_settings("workers"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(func, args, repeat(len(args)))
        for result in results:
            if result:
                logging.error(result)


# We can try delete a project that was removed, so don't bother with errors
def delete_built_rpms(cs, lp_name):
    try:
        for arch in cs.archs:
            shutil.rmtree(Path(cs.get_ccp_dir(lp_name), arch, "rpm"), ignore_errors=True)
    except KeyError:
        pass


def prj_prefix(lp_name, osc):
    return f"home:{osc.username}:{lp_name}-klp"


# The projects has different format: 12_5u5 instead of 12.5u5
def get_projects(osc, lp_name, lp_filter):
    prjs = []
    prefix = prj_prefix(lp_name, osc)

    projects = osc.search.project(f"starts-with(@name, '{prefix}')")

    for prj in projects.findall("project"):
        prj_name = prj.get("name")
        cs = convert_prj_to_cs(prj_name, prefix)

        if lp_filter and not re.match(lp_filter, cs):
            continue

        prjs.append(prj)

    return prjs


def get_project_names(osc, lp_name, lp_filter):
    names = []
    i = 1
    for result in get_projects(osc, lp_name, lp_filter):
        names.append((i, result.get("name")))
        i += 1

    return natsorted(names, key=itemgetter(1))


def get_cs_packages(cs_list, dest):
    # The packages that we search for are:
    # kernel-(default|rt)
    # kernel-(default|rt)-devel
    # kernel-(default|rt)-livepatch-devel (for SLE15+)
    # kernel-default-kgraft (for SLE12)
    # kernel-default-kgraft-devel (for SLE12)
    cs_data = {
        "kernel-default": r"(kernel-(default|rt)\-((livepatch|kgraft)?\-?devel)?\-?[\d\.\-]+.(s390x|x86_64|ppc64le).rpm)",
    }

    rpms = []
    i = 1

    osc = Osc(url="https://api.suse.de")

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

                if cs.repo != "standard":
                    pkg = f"{pkg}.{cs.repo}"

                ret = osc.build.get_binary_list(cs.project, cs.repo, arch, pkg)
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
                    if "kernel-default-devel" in rpm:
                        if arch != ARCH:
                            continue

                    rpms.append((osc, i, cs, cs.project, cs.repo, arch, pkg, rpm, dest))
                    i += 1

    return rpms


def find_missing_symbols(cs, arch, lp_mod_path):
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


def validate_livepatch_module(cs, arch, rpm_dir, rpm):
    fdest = Path(rpm_dir, rpm)
    # Extract the livepatch module for later inspection
    subprocess.check_output(f"rpm2cpio {fdest} | cpio --quiet -uidm",
                            shell=True, cwd=rpm_dir)

    # There should be only one .ko file extracted
    lp_mod_path = sorted(rpm_dir.glob("**/*.ko"))[0]

    funcs = find_missing_symbols(cs, arch, lp_mod_path)
    if funcs:
        logging.warning('%s:%s Undefined functions: %s', cs.full_cs_name(), arch, " ".join(funcs))

    shutil.rmtree(Path(rpm_dir, "lib"), ignore_errors=True)


def download_binary_rpms(args, total):
    osc, i, cs, prj, repo, arch, pkg, rpm, dest = args

    try:
        osc.build.download_binary(prj, repo, arch, pkg, rpm, dest)
        logging.info("(%d/%d) %s %s: ok", i, total, cs.full_cs_name(), rpm)
    except OSError as e:
        if e.errno == errno.EEXIST:
            logging.info("(%d/%d) %s %s: already downloaded. skipping", i, total, cs.full_cs_name(), rpm)
        else:
            raise RuntimeError(f"download error on {prj}: {rpm}") from e


def download_and_extract(args, total):
    _, i, cs, _, _, arch, _, rpm, dest = args

    # Try to download and extract at least twice if any problems arise
    tries = 2
    while tries > 0:
        download_binary_rpms(args, total)
        try:
            extract_rpms((i, cs, arch, rpm, dest), total)
            # All good, stop the loop
            break
        except Exception as e:
            # There was an issue when extracting the RPMs, probably because it's broken
            # Remove the downloaded RPMs and try again
            tries = tries - 1
            logging.info("Problem to extract %s. Downloading it again", rpm)
            Path(dest, rpm).unlink()

    if tries == 0:
        raise RuntimeError(f"Failed to extract {rpm}. Aborting")


def delete_project(osc, i, total, prj, verbose=True):
    try:
        ret = osc.projects.delete(prj, force=True)
        if not isinstance(ret, bool):
            logging.error(etree.tostring(ret))
            raise ValueError(prj)
    except requests.exceptions.HTTPError as e:
        # project not found, no problem
        if e.response.status_code == 404:
            pass

    if verbose:
        logging.info("(%d/%d) %s deleted", i, total, prj)


def delete_projects(osc, prjs, verbose=True):
    total = len(prjs)
    for i, prj in prjs:
        delete_project(osc, i, total, prj, verbose)


def extract_rpms(args, total):
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

    logging.info("(%d/%d) extracted %s %s: ok", i, total, cs.full_cs_name(), rpm)


def download_cs_rpms(cs_list):
    dest = get_datadir()/"kernel-rpms"
    dest.mkdir(exist_ok=True, parents=True)

    rpms = get_cs_packages(cs_list, dest)

    logging.info("Downloading %s rpms...", len(rpms))
    do_work(download_and_extract, rpms)

    # Create a list of paths pointing to lib/modules for each downloaded
    # codestream
    for cs in cs_list:
        for arch in cs.archs:
            # Extract modules and vmlinux files that are compressed
            mod_path = cs.get_mod_path(arch)
            logging.info("extracting %s:%s in %s", arch, cs.full_cs_name(), str(mod_path))
            for fext, ecmd in [("zst", "unzstd --rm -f -d"), ("xz", "xz --quiet -d -k")]:
                cmd = rf'find {mod_path} -name "*.{fext}" -exec {ecmd} --quiet {{}} \;'
                subprocess.check_output(cmd, shell=True)

            # Extract gzipped files per arch
            files = ["vmlinux", "symvers"]
            for f in files:
                f_path = cs.get_boot_file(f"{f}.gz", arch)
                # ppc64le doesn't gzips vmlinux
                if f_path.exists():
                    logging.info("extracting %s:%s:%s", arch, cs.full_cs_name(), f)
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
