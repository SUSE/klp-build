# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

import logging
import shutil

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.utils import (filter_codestreams,
                                   get_lp_groups)
from klpbuild.klplib.kgraft import (find_lp_branches,
                                    delete_lp_branches,
                                    create_lp_branch,
                                    commit_lp_changes,
                                    get_kgraft,
                                    init_kgraft)

PLUGIN_CMD = "commit"


def register_argparser(subparser):
    fmt = subparser.add_parser(
        PLUGIN_CMD, help="Commit the extracted livepatches to kgraft repository."
    )

    add_arg_lp_name(fmt)
    add_arg_lp_filter(fmt)
    fmt.add_argument("--force", "-f", action="store_true",
                     help="Overwrite existing livepatches in kgraft repository.")


def commit(lp_name, codestreams, force):
    init_kgraft()

    branches = find_lp_branches(f"{lp_name}_*")
    if branches and not force:
        branches_str = '\n\t' + '\n\t'.join(branches)
        logging.info("Found already commited livepatches: %s", branches_str)
        return

    logging.info("Commiting livepatch to kgraft...")

    delete_lp_branches(branches)

    for group, cs_list in get_lp_groups(lp_name, codestreams).items():
        # Create git branch and add+commit livepatch dir
        branch = f"{lp_name}_{group.replace(' ', '_')}"
        create_lp_branch(branch)

        code_path = cs_list[0].get_lp_dir(lp_name)
        shutil.copytree(code_path, f"{get_kgraft()}/{lp_name}", dirs_exist_ok=True)
        commit_lp_changes(lp_name)
        logging.info("Livepatch '%s' commited", branch)


def run(lp_name, lp_filter, force):
    supported_codestreams = get_supported_codestreams()
    filtered_codestreams = filter_codestreams(lp_filter, supported_codestreams)

    commit(lp_name, filtered_codestreams, force)
