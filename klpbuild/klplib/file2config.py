# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
#
# Copied from kernel-source:scripts/file2config.py

import re

from pathlib import Path

def _load_makefile(cs, make_file: str) -> list:

    if not cs.check_file_exists(make_file):
        return []

    buffer = cs.read_file(make_file)
    assert buffer

    joined = re.sub(r'\\\s*\n[^:]', ' ', buffer)

    lines = joined.split('\n')

    return lines


def _sanitize_config(target):
    config = target.strip('+=').strip().strip('obj-$(){}:').strip()
    return config


def _find_config(cs, base_dir, relative_obj_path, deep):
    if deep > 10:
        return None, ""

    if Path(".") == base_dir:
        return "CONFIG_SUSE_KERNEL", "vmlinux"

    make_file = Path(base_dir, "Makefile")

    lines = _load_makefile(cs, make_file)

    if not lines:
        relative_obj_path = base_dir.name + "/" + relative_obj_path
        return _find_config(cs, base_dir.parent, relative_obj_path, deep+1)

    for line in lines:
        sep = line.split()
        if relative_obj_path not in sep:
            continue

        # target found, check if this one with config
        target = sep[0]
        if target.startswith('obj-y'):
            # If it's built-in then check the config of the parent directory
            return _find_config(cs, base_dir.parent, base_dir.name + '/', deep)
        if target.startswith('obj-'):
            return _sanitize_config(target), str((base_dir/relative_obj_path).with_suffix(''))

        # target contains another object file rule, so strip it would and try
        # again
        try:
            target, _ = target.rsplit('-', 1)
        except ValueError:
            continue

        return _find_config(cs, base_dir, target + '.o', deep + 1)

    return None, ""


def find_configs_for_files(cs, file_paths: list):

    configs = {}
    build_ins = []
    missing = []

    if not file_paths:
        return configs, missing

    for path in file_paths:
        path = path.strip()
        # Do not check headers
        if path.endswith('h'):
            continue
        obj_file = Path(path.replace('.c', '.o'))
        config, obj = _find_config(cs, obj_file.parent, obj_file.name, 0)
        if not config:
            missing.append(path)
        elif config.startswith('CONFIG_'):
            configs[path] = {'config': config, 'obj': obj}
        # else there is garbage like 'subst', 'vds' for wrongly parsed input

    return configs, missing
