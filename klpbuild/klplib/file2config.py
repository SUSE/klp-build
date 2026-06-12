# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
#
# Copied from kernel-source:scripts/file2config.py

import re

from pathlib import Path


archs_config = {
        's390x': {'conf': "CONFIG_S390", 'module': 'vmlinux'},
        'x86_64': {'conf': "CONFIG_X86_64", 'module': 'vmlinux'},
        'ppc64le': {'conf': "CONFIG_PPC64", 'module': 'vmlinux'},
}


BLACKLIST = {
        r"drivers/gpu/drm/amd/(?!amdgpu/).*":
        "drivers/gpu/drm/amd/amdgpu/amdgpu_irq.c"
}


def _filter_path(path: str) -> str:
    for regex, fixed_path in BLACKLIST.items():
        if re.match(regex, path):
            return fixed_path

    return path


def _get_arch_in_path(path: str) -> str:
    if "s390" in path:
        return "s390x"
    if "x86" in path:
        return "x86_64"
    if "powerpc" in path:
        return "ppc64le"

    return None


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


def find_file_config(cs, path):
    path = path.strip()

    # Do not check headers
    if path.endswith('h'):
        return '', ''

    valid_path = _filter_path(path)
    obj_file = Path(valid_path.replace('.c', '.o'))
    config, obj = _find_config(cs, obj_file.parent, obj_file.name, 0)
    if not config:
        return '', ''

    # Detect code that is only enabled on a specific architecture.
    # Use a per-architecture generic CONFIG only if the found CONFIG
    # does not affect the same architecture as the one indicated in
    # the given file path.
    elif path.startswith("arch"):
        archs = cs.get_all_configs(config)
        arch = _get_arch_in_path(path)
        if arch and (len(archs) != 1 or not archs.get(arch)):
            return archs_config[arch]['conf'], archs_config[arch]['module']

    elif not config.startswith('CONFIG_'):
        # Garbage like 'subst', 'vds' for wrongly parsed input
        return '', ''

    return config, obj


def find_files_config(cs, file_paths: list):

    configs = {}
    missing = []

    if not file_paths:
        return configs, missing

    for path in file_paths:
        config, obj = find_file_config(cs, path)
        if config:
            configs[path] = {'conf': config, 'module': obj}
        else:
            missing.append(path)

    return configs, missing
