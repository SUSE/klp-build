# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from pathlib import Path
import json

from klpbuild.klplib.affected_file import AffectedConfig, AffectedFile, AffectedModule
from klpbuild.klplib.utils import get_workdir


class FakeCS:
    def __init__(self, files=None, cs_name="15.4u0", ibt=False, mods=None,
                 configs=None, modules=None, patches=None, branch="main",
                 supported=None):
        self.files: dict[str, AffectedFile] = files or {}
        self._cs_name = cs_name
        self._ibt = ibt
        self._mods = mods or {}
        self.configs: dict[str, AffectedConfig] = configs or {}
        self.modules: dict[str, AffectedModule] = modules or {}
        self._patches = patches or []
        self._branch = branch
        self._supported = supported or {}
        self._mod_cache: dict[str, AffectedModule] = {}

    def full_cs_name(self):
        return self._cs_name

    def needs_ibt(self):
        return self._ibt

    def lp_out_file(self, lp, f):
        return f"{lp}_{f.replace('/', '_').replace('-', '_')}"

    def get_file_mod(self, f, arch=None):
        # Mirrors Codestream.get_file_mod: returns an AffectedModule, with the
        # same instance returned across calls so cache_obj_path mutations stay
        # visible (matching Codestream.modules.setdefault semantics).
        name = self._mods.get(f, AffectedModule.VMLINUX)
        if name not in self._mod_cache:
            self._mod_cache[name] = (
                AffectedModule.vmlinux() if name == AffectedModule.VMLINUX
                else AffectedModule(name)
            )
        return self._mod_cache[name]

    def get_required_patches(self):
        return self._patches

    def get_base_branch(self):
        return self._branch

    def set_configs(self, config_names):
        for c in config_names:
            if c not in self.configs:
                self.configs[c] = AffectedConfig(c)

    def is_module_supported(self, mod):
        return self._supported.get(mod, (True, False))


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
