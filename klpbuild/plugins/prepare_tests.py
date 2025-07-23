# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import importlib
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys

from natsort import natsorted
from osctiny import Osc

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.codestreams_data import get_codestream_by_name, get_codestreams_dict
from klpbuild.klplib.ibs import convert_prj_to_cs, delete_built_rpms, delete_project, do_work, download_binary_rpms, get_projects, prj_prefix, validate_livepatch_module
from klpbuild.klplib.utils import ARCHS, filter_codestreams, get_tests_path, get_workdir

PLUGIN_CMD = "prepare-tests"


def register_argparser(subparser):
    test = subparser.add_parser(
        PLUGIN_CMD,
        help="Download the built tests and check for LP dependencies",
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

                rpms.append((osc, i, cs, prj, "standard", arch, "klp", rpm, dest))
                i += 1

    logging.info("Downloading %d packages...", len(rpms))
    do_work(download_binary_rpms, rpms)

    logging.info("Download finished.")


def prepare_tests(lp_name, lp_filter):
    # Download all built rpms
    download_built_rpms(lp_name, lp_filter)

    test_src = get_tests_path(lp_name)
    run_test = importlib.resources.files("scripts") / "run-kgr-test.sh"

    logging.info("Validating the downloaded RPMs...")

    for arch in ARCHS:
        tests_path = get_workdir(lp_name)/"tests"/arch
        test_arch_path = tests_path/lp_name

        # Remove previously created directory and archive
        shutil.rmtree(test_arch_path, ignore_errors=True)
        shutil.rmtree(f"{str(test_arch_path)}.tar.xz", ignore_errors=True)

        test_arch_path.mkdir(exist_ok=True, parents=True)
        shutil.copy(run_test, test_arch_path)

        for d in ["built", "repro", "tests.out"]:
            Path(test_arch_path, d).mkdir(exist_ok=True)

        logging.info("Checking %s symbols...", arch)
        build_cs = []
        for cs in filter_codestreams(lp_filter, get_codestreams_dict()):
            if arch not in cs.archs:
                continue

            rpm_dir = Path(cs.get_ccp_dir(lp_name), arch, "rpm")
            if not rpm_dir.exists():
                logging.info("%s/%s: rpm dir not found. Skipping.", cs.full_cs_name(), arch)
                continue

            # TODO: there will be only one rpm, format it directly
            rpm = os.listdir(rpm_dir)
            if len(rpm) > 1:
                raise RuntimeError(f"ERROR: {cs.full_cs_name()}/{arch}. {len(rpm)} rpms found. Excepting to find only one")

            for rpm in os.listdir(rpm_dir):
                # Check for dependencies
                validate_livepatch_module(cs, arch, rpm_dir, rpm)

                shutil.copy(Path(rpm_dir, rpm), Path(test_arch_path, "built"))

            if cs.rt and arch != "x86_64":
                continue

            build_cs.append(cs.get_full_product_name())

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
            f.write("\n".join(natsorted(build_cs)))

        logging.info("Creating %s tar file...", arch)
        subprocess.run(
            ["tar", "-cJf", f"{lp_name}.tar.xz", f"{lp_name}"],
            cwd=tests_path,
            stdout=sys.stdout,
            stderr=subprocess.PIPE,
            check=True,
        )

        logging.info("Done.")


def run(lp_name, lp_filter):
    prepare_tests(lp_name, lp_filter)
