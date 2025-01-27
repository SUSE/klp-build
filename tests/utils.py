# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from pathlib import Path
import json

from klpbuild.klplib.utils import get_workdir


def get_file_content(lp_name, lp_filter, fname=None):
    # Check the generated LP files
    path = get_workdir(lp_name)/"ccp"/lp_filter/"lp"

    if not fname:
        fname = f'livepatch_{lp_name}.c'

    with open(Path(path, fname)) as f:
        return f.read()


def get_codestreams_file(lp_name):
    with open(get_workdir(lp_name)/"codestreams.json") as f:
        return json.loads(f.read())
