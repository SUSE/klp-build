# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
#
# Copied from kernel-source:scripts/file2config.py

import re

from pathlib import Path

from klpbuild.klplib.affected_file import AffectedModule, ConfigState


archs_config = {
        's390x': {'conf': "CONFIG_S390", 'module': AffectedModule.VMLINUX},
        'x86_64': {'conf': "CONFIG_X86_64", 'module': AffectedModule.VMLINUX},
        'ppc64le': {'conf': "CONFIG_PPC64", 'module': AffectedModule.VMLINUX},
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
    m = re.search(r'CONFIG_\w+', target)
    return m.group(0) if m else None


def has_targets(make_lines):
    """
    Check if there are any objects (*.o) or dir reference in a makefile.
      - obj-$(CONFIG_TLS) += tls.o — contains .o
      - mlx5_core-y := main.o cmd.o debugfs.o — contains .o
      - obj-y += steering/ — ends with / (subdirectory reference)
    Not valid:
      - subdir-ccflags-y += -I$(src)/..
      - # SPDX-License-Identifier: GPL-2.0-only
    """
    return make_lines and\
           any('.o' in l or l.endswith('/') for l in make_lines)


def _find_config(cs, base_dir, relative_obj_path, deep):
    """
    Walk up the directory tree looking for the CONFIG option that enables
    a given .o file. At each level, load the Kbuild or Makefile and search
    for the object. If the target has a CONFIG (e.g. obj-$(CONFIG_TLS)),
    return it. If it's unconditionally built (e.g. obj-y, setup-y), move
    to the parent directory. Reaches the tree root as a last resort.
    """

    if deep > 10:
        return None, ""

    if Path(".") == base_dir:
        return "CONFIG_SUSE_KERNEL", AffectedModule.VMLINUX

    lines = _load_makefile(cs, Path(base_dir, "Kbuild"))
    if not lines:
        lines = _load_makefile(cs, Path(base_dir, "Makefile"))

    # Skip Makefiles with no build targets (e.g. only compiler flags)
    if not has_targets(lines):
        relative_obj_path = base_dir.name + "/" + relative_obj_path
        return _find_config(cs, base_dir.parent, relative_obj_path, deep+1)

    for line in lines:
        sep = line.split()
        # Strip variable prefixes like $(obj)/ from tokens
        tokens = [re.sub(r'\$[\({][^)}]*[\)}]/', '', t) for t in sep]
        if relative_obj_path not in tokens:
            continue

        # target found, check if it has a CONFIG option
        target = sep[0]

        config = _sanitize_config(target)
        if config:
            return config, str((base_dir/relative_obj_path).with_suffix(''))

        # Unconditionally built (e.g. obj-y, setup-y): check if the target
        # groups multiple .o files, otherwise check the parent directory
        target = re.sub(r'[:+]?=$', '', target)
        if re.match(r'\w+-y$', target):
            filename = target.rsplit('-', 1)[0]
            config, obj = _find_config(cs, base_dir, filename + '.o', deep + 1)
            if config:
                return config, obj
            return _find_config(cs, base_dir.parent, base_dir.name + '/', deep)

        # target contains another object file rule, strip the suffix and retry
        try:
            target, _ = target.rsplit('-', 1)
        except ValueError:
            continue

        return _find_config(cs, base_dir, target + '.o', deep + 1)

    # Directory reference not found here, keep searching upward
    if relative_obj_path.endswith('/'):
        relative_obj_path = base_dir.name + "/" + relative_obj_path
        return _find_config(cs, base_dir.parent, relative_obj_path, deep + 1)

    return None, ""


def _find_including_obj(cs, base_dir, c_filename, lines):
    """
    Search .c files listed in the Makefile for one that #includes the
    given c_filename. Return the matching .o, or None.
    """

    obj_files = set()
    for line in lines:
        for token in line.split():
            if token.endswith('.o'):
                obj_files.add(token)

    for obj in obj_files:
        c_file = str(Path(base_dir, obj.replace('.o', '.c')))
        if not cs.check_file_exists(c_file):
            continue
        content = cs.read_file(c_file)
        if content and f'#include "{c_filename}"' in content:
            return obj

    return None


def _find_config_include(cs, base_dir, relative_obj_path):
    """
    Fallback for .c files not listed in the Makefile. Some kernel source
    files are #included by other .c files instead of being compiled
    directly. Search sibling .c files for an #include of the target,
    and resolve the config for the including file instead.
    """

    if not relative_obj_path.endswith('.o'):
        return None, ""

    lines = _load_makefile(cs, Path(base_dir, "Makefile"))
    if not lines:
        return None, ""

    c_filename = relative_obj_path.replace('.o', '.c')
    including_obj = _find_including_obj(cs, base_dir, c_filename, lines)
    if not including_obj:
        return None, ""

    return _find_config(cs, base_dir, including_obj, 0)


def find_file_config(cs, path):

    path = path.strip()

    # Do not check headers
    if path.endswith('h'):
        return '', ''

    valid_path = _filter_path(path)
    obj_file = Path(valid_path.replace('.c', '.o'))

    config, obj = _find_config(cs, obj_file.parent, obj_file.name, 0)
    if not config:
        config, obj = _find_config_include(cs, obj_file.parent, obj_file.name)

    # Detect code that is only enabled on a specific architecture.
    # Use a per-architecture generic CONFIG only if the found CONFIG
    # does not affect the same architecture as the one indicated in
    # the given file path.
    elif path.startswith("arch"):
        arch = _get_arch_in_path(path)
        cfg = cs.get_all_configs(config)
        if arch and (len(cfg.archs()) != 1 or cfg.get_arch(arch) is ConfigState.NOT_SET):
            return archs_config[arch]['conf'], archs_config[arch]['module']

    if not config or not config.startswith('CONFIG_'):
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
