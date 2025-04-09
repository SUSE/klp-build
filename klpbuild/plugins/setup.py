# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import logging
from pathlib import Path
from natsort import natsorted

from klpbuild.klplib import utils
from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.codestreams_data import get_codestreams_data, set_codestreams_data, store_codestreams
from klpbuild.klplib.kernel_tree import update_kernel_tree_tags
from klpbuild.klplib.templ import generate_commit_msg_file

from klpbuild.plugins.scan import scan

PLUGIN_CMD = "setup"

def register_argparser(subparser):
    setup = subparser.add_parser(
        PLUGIN_CMD, help="Establish an initial working directory for a given livepatch"
    )
    add_arg_lp_name(setup)
    add_arg_lp_filter(setup)
    setup.add_argument("--cve", type=str, help="The CVE assigned to this livepatch")
    setup.add_argument("--conf", type=str, required=True, help="The kernel CONFIG used to be build the livepatch")
    setup.add_argument(
        "--no-check",
        action="store_true",
        help="Do not check for already patched codestreams, do the setup for all non filtered codestreams.",
    )
    setup.add_argument(
        "--file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="File and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs file/path.c func1 "
        "func2 --file-func file/patch2 func1...",
    )
    setup.add_argument(
        "--mod-file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="Module, file and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs module1 file/path.c func1 "
        "func2 --file-func module2 file/patch2 func1...",
    )
    setup.add_argument(
        "--conf-mod-file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="Conf, module, file and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs conf1 module1 file/path.c func1 "
        "func2 --file-func conf2 module2 file/patch2 func1...",
    )
    setup.add_argument(
        "--module", type=str, default="vmlinux", help="The module that will be livepatched for all files"
    )
    setup.add_argument(
        "--archs",
        default=utils.ARCHS,
        choices=utils.ARCHS,
        nargs="+",
        help="Supported architectures for this livepatch",
    )


def run(lp_name, lp_filter, no_check, archs, cve, conf, module, file_funcs,
        mod_file_funcs, conf_mod_file_funcs):

    return setup(lp_name, lp_filter, no_check, archs, cve, conf, module,
                 file_funcs, mod_file_funcs, conf_mod_file_funcs)

def setup(lp_name, lp_filter, no_check, archs, cve, conf, module, file_funcs,
          mod_file_funcs, conf_mod_file_funcs):
    assert isinstance(archs, list)

    lp_path = utils.get_workdir(lp_name)
    if lp_path.exists() and not lp_path.is_dir():
        raise ValueError("--name needs to be a directory, or not to exist")

    ffuncs = setup_file_funcs(conf, module, file_funcs,
                                    mod_file_funcs, conf_mod_file_funcs)

    codestreams = setup_codestreams(lp_name, {"cve": cve, "conf": conf,
                                              "lp_filter": lp_filter,
                                              "no_check": no_check})
    setup_project_files(lp_name, codestreams, ffuncs, archs)

def setup_file_funcs(conf, mod, file_funcs, mod_file_funcs, conf_mod_file_funcs):
    if conf and not conf.startswith("CONFIG_"):
        raise ValueError("Please specify --conf with CONFIG_ prefix")

    if not file_funcs and not mod_file_funcs and not conf_mod_file_funcs:
        raise ValueError("You need to specify at least one of the file-funcs variants!")

    ffuncs = {}
    for f in file_funcs:
        filepath = f[0]
        funcs = f[1:]

        ffuncs[filepath] = {"module": mod, "conf": conf, "symbols": funcs}

    for f in mod_file_funcs:
        fmod = f[0]
        filepath = f[1]
        funcs = f[2:]

        ffuncs[filepath] = {"module": fmod, "conf": conf, "symbols": funcs}

    for f in conf_mod_file_funcs:
        fconf = f[0]
        fmod = f[1]
        filepath = f[2]
        funcs = f[3:]

        ffuncs[filepath] = {"module": fmod, "conf": fconf, "symbols": funcs}

    return ffuncs

def setup_codestreams(lp_name, data):
    if not lp_name.startswith("bsc"):
        raise ValueError("Please use prefix 'bsc' when creating a livepatch for codestreams")

    # Called at this point because codestreams is populated
    # FIXME: we should check all configs, like when using --conf-mod-file-funcs
    commits, patched_cs, patched_kernels, codestreams = scan(data["cve"],
                                                             data["conf"],
                                                             data["no_check"],
                                                             data["lp_filter"],
                                                             True,
                                                             utils.get_workdir(lp_name))
    # Add new codestreams to the already existing list, skipping duplicates
    old_patched_cs = get_codestreams_data('patched_cs')
    new_patched_cs = natsorted(list(set(old_patched_cs + patched_cs)))

    set_codestreams_data(commits=commits, patched_kernels=patched_kernels,
                         patched_cs=new_patched_cs, cve=data['cve'])
    return codestreams


def setup_project_files(lp_name, codestreams, ffuncs, archs):
    utils.get_workdir(lp_name).mkdir(exist_ok=True)
    update_kernel_tree_tags()

    archs.sort()
    set_codestreams_data(archs=archs)

    logging.info("Affected architectures:")
    logging.info("\t%s", ' '.join(archs))

    generate_commit_msg_file(lp_name)

    logging.info("Checking files, symbols, modules...")
    # Setup the missing codestream info needed
    for cs in codestreams:
        cs.set_files(copy.deepcopy(ffuncs))

        # Check if the files exist in the respective codestream directories
        mod_syms = {}
        for f, fdata in cs.files.items():

            mod = fdata["module"]
            cs.validate_config(archs, fdata["conf"], mod)

            cs.check_file_exists(f)

            ipa_f = cs.get_ipa_file(f)
            if not ipa_f.is_file():
                ipa_f.touch()
                logging.warning("%s (%s): File %s not found. Creating an empty file.", cs.name(), cs.kernel, ipa_f)

            # If the config was enabled on all supported architectures,
            # there is no point in leaving the conf being set, since the
            # feature will be available everywhere.
            if archs == utils.ARCHS:
                fdata["conf"] = ""

            mod_path = cs.find_obj_path(utils.ARCH, mod)

            # Validate if the module being livepatched is supported or not
            if utils.check_module_unsupported(utils.ARCH, mod_path):
                logging.warning("%s (%s}): Module %s is not supported by SLE", cs.name(), cs.kernel, mod)

            cs.modules[mod] = str(mod_path)
            mod_syms.setdefault(mod, [])
            mod_syms[mod].extend(fdata["symbols"])

        # Verify if the functions exist in the specified object
        for mod, syms in mod_syms.items():
            arch_syms = cs.check_symbol_archs(archs, mod, syms, False)
            if arch_syms:
                for arch, syms in arch_syms.items():
                    logging.warning("%s-%s (%s): Symbols %s not found on %s object",
                                    cs.name(), arch, cs.kernel, ",".join(syms), mod)

    store_codestreams(lp_name, codestreams)
    logging.info("Done. Setup finished.")
