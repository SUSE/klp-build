# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

import logging
import shutil
import sys

from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.codestreams_data import get_codestreams_list
from klpbuild.klplib.utils import (filter_codestreams,
                                   get_lp_groups)
from klpbuild.klplib.kgraft import (find_lp_branches,
                                    delete_lp_branches,
                                    create_lp_branch,
                                    commit_lp_changes,
                                    get_kgraft,
                                    init_kgraft,
                                    reset_kgraft)

PLUGIN_CMD = "commit"


def register_argparser(subparser):
    fmt = subparser.add_parser(
        PLUGIN_CMD, help="Commit the extracted livepatches to kgraft repository."
    )

    add_arg_lp_name(fmt)
    add_arg_lp_filter(fmt)
    fmt.add_argument("--force", "-f", action="store_true",
                     help="Overwrite existing livepatches in kgraft repository.")


def _group_branch(lp_name, group):
    return f"{lp_name}_{group.replace(' ', '_')}"


def commit(lp_name, codestreams, force):
    for cs in codestreams:
        if "x86_64" not in cs.archs:
            logging.error("Codestream '%s' does not affect x86_64", cs.full_cs_name())
            sys.exit(1)

    init_kgraft()

    groups = get_lp_groups(lp_name, codestreams)

    # Only consider the branches of the groups that are going to be
    # (re)created, so that a filtered run never touches the others.
    targets = {_group_branch(lp_name, group) for group in groups}
    existing = find_lp_branches(f"{lp_name}_*") or []
    branches = [b for b in existing if b in targets]

    if branches and not force:
        branches_str = '\n\t' + '\n\t'.join(branches)
        logging.info("Found already commited livepatches: %s", branches_str)
        return

    logging.info("Commiting livepatch to kgraft...")

    if branches:
        logging.info("Overwriting existing branches: %s",
                     '\n\t' + '\n\t'.join(branches))
    delete_lp_branches(branches)

    for group, cs_list in groups.items():
        # Create git branch and add+commit livepatch dir
        branch = _group_branch(lp_name, group)
        create_lp_branch(branch)

        code_path = cs_list[0].get_lp_dir(lp_name)
        shutil.copytree(code_path, f"{get_kgraft()}/{lp_name}", dirs_exist_ok=True)
        commit_lp_changes(lp_name)
        logging.info("Livepatch '%s' commited", branch)

    reset_kgraft()


def run(lp_name, lp_filter, force):
    cs_list = filter_codestreams(lp_filter, get_codestreams_list())
    if not cs_list:
        logging.error("commit: No codestreams found")
        sys.exit(1)

    commit(lp_name, cs_list, force)
