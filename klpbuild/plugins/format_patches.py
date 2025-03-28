# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import shutil
import subprocess

from klpbuild.klplib import utils
from klpbuild.klplib.cmd import add_arg_lp_name
from klpbuild.klplib.config import get_user_path

PLUGIN_CMD = "format-patches"

def register_argparser(subparser):
    fmt = subparser.add_parser(
        "format-patches", help="Format patches from kgraft-patches[_testscripts]"
    )
    add_arg_lp_name(fmt)
    fmt.add_argument("-v", "--version", type=int, required=True, help="Version to be added, like vX")


def run(lp_name, version):
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
        logging.info(branch)
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
