# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

import logging
import re

from pathlib import PurePosixPath
from collections import defaultdict

from klpbuild.klplib import utils
from klpbuild.klplib.file2config import find_file_config
from klpbuild.klplib.ksrc import get_patches_files


__FUNC_FINDER_RE = re.compile(r"\s*(\w+)\s*\([^(]*\)\n\+*\s*\{\n")


def analyse_files(cs_list):
    '''
    Function that analyses, per codestream, each of the files modified
    by the backported patches.
    For each of the files it retrieves the corresponding kernel module
    config and modified functions.
    Lastly, it returns back a report grouping the codestreams by files,
    modules, configs and modified functions.

    Args:
        cs_list (list): List of affected codestreams.
    '''

    report = defaultdict(list)

    for cs in cs_list:
        patches = [f"patches.suse/{p}" for p in cs.get_required_patches()]
        branch = cs.get_base_branch()
        files = get_patches_files(patches, branch)
        cs_report = __analyse_cs_files(cs, files)
        for key in cs_report:
            if key not in report:
                report[key] = []
            report[key].append(cs)

    return report


def __analyse_cs_files(cs, files):

    report = []

    for file, diffs in files.items():
        conf, obj = find_file_config(cs, file)
        funcs = __extract_functions(diffs)
        if conf:
            cs.files[file] = {'symbols': list(funcs),
                              'conf': conf, 'module': obj}
            key = f"{file}:{conf}:{obj}:{sorted(funcs)}"
        else:
            key = f"{file}:::"
            logging.warning("%s: Failed to find a config for %s",
                            cs.full_cs_name(), file)

        report.append(key)

    return report


def __extract_functions(diffs):
    """
    Return the set of function names actually modified across `diffs`.

    Each diff is the `git show -W` output for one patch touching a
    single file. For each signature, walk its body line by line,
    balancing braces. Extract the function only if the body has
    been modified (+/- line).
    """

    def is_change(line):
        return line.startswith(("+", "-")) and not line.startswith(("+++", "---"))

    def get_content(line):
        return line[1:] if line[:1] in "+- " else line

    funcs = set()
    for diff in diffs:
        for sig in __FUNC_FINDER_RE.finditer(diff):
            depth = 1  # the opening '{'
            modified = False
            for line in diff[sig.end():].splitlines():
                # A hunk boundary here means the body wasn't included
                if line.startswith(("@@", "diff ")):
                    break
                if is_change(line):
                    modified = True
                    break
                content = get_content(line)
                depth += content.count("{") - content.count("}")
                if depth == 0:
                    break # Outside of the body

            if modified:
                funcs.add(sig.group(1))

    return funcs


def print_files(report):

    for key, cs_list in report.items():
        cs = cs_list[0]
        cs_str = utils.classify_codestreams_str(cs_list)
        file = key.split(':')[0]

        if not cs.files or file not in cs.files:
            logging.info("%s:\nFILE: %s\n", cs_str, file)
            continue

        conf = cs.files[file]['conf']
        obj = cs.files[file]['module']
        funcs = cs.files[file]['symbols']
        logging.info("%s:\nFILE: %s\nCONF: %s\nOBJ: %s\nFUNCS: %s\n",
                     cs_str, file, conf, obj, ', '.join(funcs))


def analyse_configs(cs_list):
    '''
    Function that analyses, per codestream, each of the CONFIGs found
    in analyse_files().
    For each of the CONFIGs it retrieves the archs where they are set,
    or if they are at all.
    Lastly, it returns back a report grouping the codestreams by CONFIGs.

    Args:
        cs_list (list): List of affected codestreams.
    '''

    report = defaultdict(list)

    for cs in cs_list:
        configs = {dat['conf'] for _, dat in cs.files.items()}
        cs.set_configs(configs)
        for conf, archs in cs.configs.items():
            key = f"{conf}:{archs}"
            if cs not in report[key]:
                report[key].append(cs)

    return report


def __get_arch_config(conf, arch):
    return conf[arch] if arch in conf else 'n'


def print_configs(report):

    for key, cs_list in report.items():
        cs = cs_list[0]
        c = key.split(':')[0]
        conf = cs.configs[c]
        x86_64 = __get_arch_config(conf, "x86_64")
        ppc64le = __get_arch_config(conf, "ppc64le")
        s390x = __get_arch_config(conf, "s390x")
        cs_str = utils.classify_codestreams_str(cs_list)
        logging.info("%s:\nCONF: %s\nx86_64: %s\nppc64le: %s\ns390x: %s\n",
                     cs_str, c, x86_64, ppc64le, s390x)


def filter_unset_configs(cs_list):

    unset_cs = []
    unset_conf = []

    for cs in cs_list:
        if not cs.configs:
            continue

        isset = [conf for conf, archs in cs.configs.items() if archs]
        if not isset:
            unset_cs.append(cs)
            unset_conf += list(cs.configs)

    for cs in unset_cs:
        cs_list.remove(cs)

    return unset_cs, sorted(set(unset_conf))


def analyse_kmodules(cs_list):
    '''
    Function that analyses, per codestream, each of the kernel modules found
    in analyse_files().
    For each of the modules it checks if they are supported, builtin and so on.
    Lastly, it returns back a report grouping the codestreams by modules and
    their configuration.

    Args:
        cs_list (list): List of affected codestreams.
    '''

    report = defaultdict(list)

    for cs in cs_list:
        for _, dat in cs.files.items():
            conf = dat['conf']
            mod = dat['module']
            if mod in cs.modules:
                continue

            # Check if it's not built-in for any arch
            if 'm' not in [val for _, val in
                           cs.configs[conf].items()]:
                continue

            supported, blacklisted = cs.is_module_supported(mod)
            if blacklisted:
                logging.warning("%s: Module '%s' is not supported by klp-build.",
                                cs.full_cs_name(), PurePosixPath(mod).name)

            cs.modules[mod] = supported
            key = f"{mod}:{supported}"
            if cs not in report[key]:
                report[key].append(cs)

    return report


def print_kmodules(report):

    for key, cs_list in report.items():
        cs = cs_list[0]
        m = key.split(':')[0]
        supported = cs.modules[m]
        cs_str = utils.classify_codestreams_str(cs_list)
        logging.info("%s:\nMOD: %s\nSupported: %s\n",
                     cs_str, m, supported)


def filter_unsupported_kmodules(cs_list):

    unset_cs = []

    for cs in cs_list:
        if not cs.modules:
            continue

        supported = [s for _, s in cs.modules.items() if s]
        if not supported:
            unset_cs.append(cs)

        # Cleanup for future re-use
        cs.modules.clear()

    for cs in unset_cs:
        cs_list.remove(cs)

    return unset_cs
