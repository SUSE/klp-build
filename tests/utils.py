# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from pathlib import Path
import json

from klpbuild.klplib.utils import get_workdir


class FakeCS:
    def __init__(self, files, cs_name="15.4u0", ibt=False, mods=None):
        self.files = files
        self._cs_name = cs_name
        self._ibt = ibt
        self._mods = mods or {}

    def full_cs_name(self):
        return self._cs_name

    def needs_ibt(self):
        return self._ibt

    def lp_out_file(self, lp, f):
        return f"{lp}_{f.replace('/', '_').replace('-', '_')}"

    def get_file_mod(self, f):
        return self._mods.get(f, "vmlinux")


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
