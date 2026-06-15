# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import concurrent.futures
import importlib
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from natsort import natsorted
from osctiny import Osc

from klpbuild.klplib.cmd import add_arg_lp_filter, add_arg_lp_name
from klpbuild.klplib.codestreams_data import (
    get_codestream_by_name,
    get_codestreams_list,
)
from klpbuild.klplib.config import get_user_settings
from klpbuild.klplib.ibs import (
    RPMData,
    convert_prj_to_cs,
    delete_built_rpms,
    delete_project,
    do_work,
    download_binary_rpms,
    get_projects,
    prj_prefix,
    validate_livepatch_module,
)
from klpbuild.klplib.utils import ARCHS, filter_codestreams, get_tests_path, get_workdir

PLUGIN_CMD = "prepare-tests"


def register_argparser(subparser):
    test = subparser.add_parser(
        PLUGIN_CMD,
        help="Download the built livepatch packages",
    )

    add_arg_lp_name(test)
    add_arg_lp_filter(test)


def download_built_rpms(lp_name, lp_filter):
    rpms = []
    i = 1
    osc = Osc(url="https://api.suse.de")

    for result in get_projects(osc, lp_name, lp_filter):
        prj = result.get("name")
        cs_name = convert_prj_to_cs(prj, prj_prefix(lp_name, osc))

        # Get the codestream from the dict
        cs = get_codestream_by_name(cs_name)
        if not cs:
            logging.info("Codestream %s is stale. Deleting it.", cs_name)
            delete_project(osc, 0, 0, prj, False)
            continue

        # Remove previously downloaded rpms
        delete_built_rpms(cs, lp_name)

        archs = result.xpath("repository/arch")
        for arch in archs:
            ret = osc.build.get_binary_list(prj, "standard", arch, "klp")
            rpm_name = f"{arch}.rpm"
            for rpm in ret.xpath("binary/@filename"):
                if not rpm.endswith(rpm_name):
                    continue

                if "preempt" in rpm:
                    continue

                # Create a directory for each arch supported
                dest = cs.get_ccp_dir(lp_name)/str(arch)/"rpm"
                dest.mkdir(exist_ok=True, parents=True)

                rpms.append(RPMData(i, osc, cs, prj, "standard", arch, "klp", rpm, dest))
                i += 1

    logging.info("Downloading %d packages...", len(rpms))
    do_work(download_binary_rpms, rpms)

    logging.info("Download finished.")


def validate_module_and_move(cs, arch, lp_name, test_arch_path):
    """
    Validate a livepatch module and move it to the test directory.

    Returns the codestream's full product name on success, None on failure.
    """
    rpm_dir = Path(cs.get_ccp_dir(lp_name), arch, "rpm")
    if not rpm_dir.exists():
        logging.warning("%s/%s: rpm dir not found. Skipping.", cs.full_cs_name(), arch)
        return None

    # Skip codestreams with more than one rpm, and none. There is an issue elsewhere.
    rpm_files = list(rpm_dir.rglob("*.rpm"))
    if len(rpm_files) != 1:
        logging.warning("%s/%s: expected 1 rpm, found %d. Skipping.", cs.full_cs_name(), arch, len(rpm_files))
        return None

    # There should be only one rpm, so take the first entry in the list
    rpm_path = rpm_files[0]
    rpm_file = rpm_path.name
    validate_livepatch_module(cs, arch, rpm_dir, rpm_file)
    shutil.move(rpm_path, Path(test_arch_path, "built"))

    return cs.get_full_product_name()


def run(lp_name, lp_filter):
    test_src = get_tests_path(lp_name)
    if test_src and not os.access(test_src, os.X_OK):
        logging.error("Script %s has no execution bit set. Aborting", test_src)
        sys.exit(1)

    # Download all built rpms
    download_built_rpms(lp_name, lp_filter)

    tests_dir = get_workdir(lp_name, True) / "tests"
    run_test = importlib.resources.files("scripts") / "run-kgr-test.sh"

    logging.info("Validating the downloaded RPMs...")

    for arch in ARCHS:
        tests_path = tests_dir / arch
        test_arch_path = tests_path/lp_name

        # Remove previously created directory and archive
        shutil.rmtree(test_arch_path, ignore_errors=True)
        shutil.rmtree(f"{str(test_arch_path)}.tar.xz", ignore_errors=True)

        test_arch_path.mkdir(exist_ok=True, parents=True)
        shutil.copy(run_test, test_arch_path)

        for d in ["built", "repro", "tests.out"]:
            Path(test_arch_path, d).mkdir(exist_ok=True)

        logging.info("Checking %s symbols...", arch)

        # Prepare list of codestreams to validate
        cs_to_validate = [
            cs for cs in filter_codestreams(lp_filter, get_codestreams_list())
            if arch in cs.get_default_archs()
        ]

        # Validate modules in parallel using processes (not threads) to avoid
        # thread-safety issues with underlying C libraries
        workers = int(get_user_settings("workers"))
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(validate_module_and_move, cs, arch, lp_name, test_arch_path)
                for cs in cs_to_validate
            ]
            concurrent.futures.wait(futures)

            # Collect successful results
            results = [future.result() for future in futures]
            validated_cs = [r for r in results if r is not None]

        logging.info("Done.")

        # Prepare the config and test files used by kgr-test
        if not test_src:
            logging.warning("No testcase found, so no tar file is being created.")
            continue

        test_dst = Path(test_arch_path, f"repro/{lp_name}")
        if test_src.is_file():
            shutil.copy(test_src, f"{test_dst}_test_script.sh")
            config = f"{test_dst}_config.in"
        else:
            # Alternatively, we create test_dst as a directory containing
            # at least a test_script.sh and a config.in
            shutil.copytree(test_src, test_dst)
            config = Path(test_dst, "config.in")

        with open(config, "w") as f:
            f.write("\n".join(natsorted(validated_cs)))

        logging.info("Creating %s tar file...", arch)
        subprocess.run(
            ["tar", "-cJf", f"{lp_name}.tar.xz", f"{lp_name}"],
            cwd=tests_path,
            stdout=sys.stdout,
            stderr=subprocess.PIPE,
            check=True,
        )

        logging.info("Done.")
