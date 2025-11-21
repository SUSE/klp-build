# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import logging
import shutil
import subprocess
import re

from klpbuild.klplib.codestreams_data import (get_codestreams_data,
                                              get_codestreams_list)
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
    fmt.add_argument("--no-test", action="store_true", default=False, help="Skip the test script.")


def run(lp_name, no_test, version):
    ver = f"v{version}"
    index = 1

    kgr_patches = get_user_path('kgr_patches_dir')

    # Remove dir to avoid leftover patches with different names
    patches_dir = utils.get_workdir(lp_name)/"patches"
    shutil.rmtree(patches_dir, ignore_errors=True)

    prefix = f"Klp-patches][PATCH {ver}"

    if not no_test:
        test_src = utils.get_tests_path(lp_name)
        if test_src:
            logging.info(test_src.name)
            subprocess.check_output(
                [
                    "/usr/bin/git",
                    "-C",
                    str(get_user_path('kgr_patches_tests_dir')),
                    "format-patch",
                    "-1",
                    "-N",
                    f"{test_src}",
                    "--cover-letter",
                    "--start-number",
                    f"{index}",
                    "--subject-prefix",
                    f"{prefix}",
                    "--output-directory",
                    f"{patches_dir}",
                ]
            )
            index += 1

    # Filter only the branches related to this BSC
    for branch in utils.get_lp_branches(lp_name, kgr_patches):
        logging.info(branch)
        bname = branch.replace(lp_name + "_", "")
        bs = " ".join(bname.split("_"))
        bsc = lp_name.replace("bsc", "bsc#")

        cmd = [
                "/usr/bin/git",
                "-C",
                str(kgr_patches),
                "format-patch",
                "-1",
                "-N",
                branch,
                "--start-number",
                f"{index}",
                "--subject-prefix",
                f"{prefix} {bsc} {bs}",
                "--output-directory",
                f"{patches_dir}",
            ]
        if index == 1:
            cmd.append("--cover-letter")

        subprocess.check_output(cmd)
        index += 1

    update_cover_letter(patches_dir, lp_name)


def update_cover_letter(patches_dir, lp_name):
    bsc = lp_name.replace("bsc", "bsc#")
    cve = get_codestreams_data('cve')
    cs_list = get_codestreams_list()
    cs_patched  = get_codestreams_data('patched_cs')

    letter_path = f"{patches_dir}/0000-cover-letter.patch"
    with open(letter_path, 'r') as f:
        letter = f.read()

    subject = f"livepatch CVE-{cve} {bsc}"
    letter = re.sub(r"\*{3} SUBJECT HERE.*", subject, letter)

    archs = ', '.join(get_codestreams_data('archs'))
    cs_patched  = utils.classify_codestreams_str(cs_patched)
    cs_affected = utils.classify_codestreams_str(cs_list)
    cs_groups = generate_groups(lp_name, cs_list)
    desc = generate_desc()

    body = "Hi team,\n\n"
    body += f"# Description:\n{desc}\n\n"
    body += f"# Affected archs:\n - {archs}\n"
    body += f"# Patched codestreams:\n - {cs_patched}\n"
    body += f"# Affeted codestreams:\n - {cs_affected}\n"
    body += f"# Grouped codestreams:\n{cs_groups}\n"
    body += f"# Manual work:\nNone\n\n"
    letter = re.sub(r"\*{3} BLURB HERE.*", body, letter, flags=re.DOTALL)

    with open(letter_path, 'w') as f:
        f.write(letter)


def generate_groups(lp_name, codestreams):
    groups = ""

    cs_groups = utils.get_lp_groups(lp_name, codestreams)
    for group, cs_list in cs_groups.items():
        groups += f" - {group}\n"
        cs = cs_list[0]
        for file, fdat in cs.files.items():
            if 'klpp_symbols' not in fdat:
                continue
            syms = '\n\t\t   '.join(sorted(fdat['klpp_symbols']))
            mod = cs.get_file_mod(file)
            groups += f"\t* File: {file}\n\t* Module: {mod}\n"\
                      f"\t* Symbols: {syms}\n"

    return groups


def generate_desc():
    upstream = get_codestreams_data('upstream')
    return "Livepatch for the following commits:\n - "\
            + '\n - '.join(upstream)
