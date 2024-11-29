# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from pathlib import Path

from klpbuild.config import Config

def get_workdir(lp_name):
    return Config(lp_name).lp_path

def get_file_content(lp_name, lp_filter, fname=None):
    # Check the generated LP files
    path = Path(get_workdir(lp_name), "ccp", lp_filter, "lp")

    if not fname:
        fname = f'livepatch_{lp_name}.c'

    with open(Path(path, fname)) as f:
        return f.read()
