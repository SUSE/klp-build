# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
#
# Copied from kernel-source:scripts/file2config.py

import re

from pathlib import Path, PurePath
from os import chdir
from argparse import ArgumentParser
from os.path import expanduser

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


def _find_config(cs, obj_path, deep):

    if deep > 10:
        return None, ""

    make_file = Path(obj_path.parent, "Makefile")

    lines = _load_makefile(cs, make_file)

    obj_name = PurePath(obj_path).name
    for line in lines:
        sep = line.split()
        if obj_name not in sep:
            continue

        # target found, check if this one with config
        target = sep[0]
        if target.startswith('obj-'):
            return _sanitize_config(target), str(obj_path.with_suffix(''))

        # target contains another object file rule, so strip it would and try
        # again
        try:
            target, _ = target.rsplit('-', 1)
        except ValueError as ve:
            # print(ve)
            continue

        return _find_config(cs, Path(obj_path.parent, target + '.o'), deep + 1)

    return None, ""


def find_configs_for_files(cs, file_paths: list):

    configs = dict()
    build_ins = []
    missing = []

    if not file_paths:
        return configs, build_ins, missing

    for path in file_paths:
        path = path.strip()
        obj_file = path.replace('.c', '.o')
        config, obj = _find_config(cs, Path(obj_file), 0)
        if not config:
            missing.append(path)
        elif config == 'y' or config == 'm':
            build_ins.append(path)
        elif config.startswith('CONFIG_'):
            configs[path] = {'config': config, 'obj': obj}
        # else there is garbage like 'subst', 'vds' for wrongly parsed input

    return configs, build_ins, missing

