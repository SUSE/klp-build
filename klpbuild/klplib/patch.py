# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

import logging

from collections import defaultdict

from klpbuild.klplib import utils
from klpbuild.klplib.file2config import find_configs_for_files
from klpbuild.klplib.ksrc import KERNEL_BRANCHES, get_patch_files


def analyse_files(cs_list, sle_patches):
    '''
    Function that analyses, per codestream, each of the files modified
    by the backported patches.
    For each of the files it retrieves the corresponding kernel module
    and config.
    Lastly, it returns back a report grouping the codestreams by files,
    modules and configs.

    Args:
        cs_list (list): List of affected codestreams.
        sle_commits (dict): List of commits by codestream.
    '''

    report = defaultdict(list)

    for cs in cs_list:
            bc = cs.base_cs_name()
            patches = sle_patches[bc]
            branch = KERNEL_BRANCHES[bc]
            files = get_patch_files(patches, branch)
            fconfigs, _, missing = find_configs_for_files(cs, files)

            for file in missing:
                key = f"{file}::"
                if cs not in report[key]:
                    report[key].append(cs)

            for file, dat in fconfigs.items():
                key = f"{file}:{dat['config']}:{dat['obj']}"
                if cs not in report[key]:
                    report[key].append(cs)

            cs.files.update(fconfigs)

    return report


def print_files(report):

    for key, cs_list in report.items():
        cs = cs_list[0]
        cs_str = utils.classify_codestreams_str(cs_list)
        file = key.split(':')[0]

        if not cs.files or file not in cs.files:
            logging.info(f"{cs_str}:\nFILE: {file}\n")
            continue

        conf = cs.files[file]['config']
        obj = cs.files[file]['obj']
        logging.info("%s:\nFILE: %s\nCONF: %s\nOBJ: %s\n",
                     cs_str, file, conf, obj)


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
        for _, dat in cs.files.items():
            conf = dat['config']
            if conf in cs.configs:
                continue

            cs.configs[conf] = cs.get_all_configs(conf)

            key = f"{conf}:{cs.configs[conf]}"
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
            unset_conf += [conf for conf in cs.configs]

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
            conf = dat['config']
            mod = dat['obj']
            if mod in cs.modules:
                continue

            # Check if it's not built-in for any arch
            if 'm' not in [val for _, val in
                           cs.configs[conf].items()]:
                continue

            supported = cs.is_module_supported(mod)
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

    for cs in unset_cs:
        cs_list.remove(cs)

    return unset_cs

