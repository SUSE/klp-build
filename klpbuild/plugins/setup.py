# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import logging
from natsort import natsorted

from klpbuild.klplib import utils
from klpbuild.klplib.cmd import add_arg_lp_name, add_arg_lp_filter
from klpbuild.klplib.codestreams_data import get_codestreams_data, set_codestreams_data, store_codestreams
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.templ import generate_commit_msg_file

from klpbuild.plugins.scan import scan

PLUGIN_CMD = "setup"

def register_argparser(subparser):
    setup = subparser.add_parser(
        PLUGIN_CMD, help="Establish an initial working directory for a given livepatch"
    )
    add_arg_lp_name(setup)
    add_arg_lp_filter(setup)
    setup.add_argument("--cve", type=str, required=True, help="The CVE assigned to this livepatch")
    setup.add_argument("--conf", type=str, required=False, help="The kernel CONFIG used to be build the livepatch")
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

    codestreams = setup_codestreams(lp_name, {"cve": cve, "conf": conf,
                                              "lp_filter": lp_filter,
                                              "no_check": no_check,
                                              "archs": archs})

    if conf:
        setup_manual(codestreams, archs, conf, module,
                     file_funcs, mod_file_funcs,
                     conf_mod_file_funcs)

    setup_archs(codestreams)
    setup_project_files(lp_name, codestreams)


def setup_manual(codestreams, archs, conf, mod,
                 file_funcs, mod_file_funcs,
                 conf_mod_file_funcs):
    if not file_funcs and not mod_file_funcs and not conf_mod_file_funcs:
        raise ValueError("You need to specify at least one of the file-funcs variants!")

    ffuncs = {}
    configs = {conf}
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

        configs.add(fconf)

        ffuncs[filepath] = {"module": fmod, "conf": fconf, "symbols": funcs}

    for cs in codestreams:
        cs.set_archs(archs)
        cs.set_files(copy.deepcopy(ffuncs))
        cs.set_configs(configs)


def setup_archs(codestreams):
    archs = utils.affected_archs(codestreams)
    set_codestreams_data(archs=archs)


def setup_codestreams(lp_name, data):
    if not lp_name.startswith("bsc"):
        raise ValueError("Please use prefix 'bsc' when creating a livepatch for codestreams")

    # Called at this point because codestreams is populated
    if data["no_check"]:
        logging.info("Option --no-check was specified, checking all codestreams that are not filtered out...")
        upstream = []
        patched_cs = []
        all_codestreams = get_supported_codestreams()
        codestreams = utils.filter_codestreams(data["lp_filter"], all_codestreams)
    else:
        _, upstream, patched_cs, codestreams = scan(data["cve"], data["conf"],
                                                    data["lp_filter"], True,
                                                    data["archs"],
                                                    utils.get_workdir(lp_name))

    # Add new codestreams to the already existing list, skipping duplicates
    old_patched_cs = get_codestreams_data('patched_cs')
    new_patched_cs = natsorted(list(set(old_patched_cs + patched_cs)))

    set_codestreams_data(upstream=upstream, patched_cs=new_patched_cs,
                         cve=data['cve'])
    return codestreams


def setup_project_files(lp_name, codestreams):
    utils.get_workdir(lp_name).mkdir(exist_ok=True)

    generate_commit_msg_file(lp_name)
    logging.info("Checking files, symbols, modules...")

    # Setup the missing codestream info needed
    for cs in codestreams:
        # Check if the files and symbols exist in the respective codestream directories
        for f, fdata in cs.files.copy().items():
            conf = fdata["conf"]
            archs = cs.configs[conf]
            syms = fdata["symbols"]
            if not len(syms):
                logging.warning("%s (%s): No symbols found for %s file."
                                " Skipping.", cs.full_cs_name(), cs.kernel, f)
                cs.files.pop(f)
                continue

            __setup_check_file(cs, f)

            for arch in archs:
                mod = cs.get_file_mod(f, arch)
                __setup_check_mod(cs, mod)
                __setup_check_syms(cs, mod, syms, arch)

        if not len(cs.files):
            raise RuntimeError(f"{cs.full_cs_name()} ({cs.kernel}):"
                               " No files eligible to be livepatched. Aborting.")

    store_codestreams(lp_name, codestreams)
    logging.info("Done. Setup finished.")


def __setup_check_file(cs, file):
    if not cs.check_file_exists(file):
        raise RuntimeError(f"{cs.full_cs_name()} ({cs.kernel}): File {file} not found.")

    ipa_f = cs.get_ipa_file(file)
    if not ipa_f.is_file():
        ipa_f.touch()
        logging.warning("%s (%s): File %s not found. Creating an empty file.",
                        cs.full_cs_name(), cs.kernel, ipa_f)


def __setup_check_mod(cs, mod):
    if mod in cs.modules:
        return

    mod_path = cs.find_obj_path(utils.ARCH, mod)

    # Validate if the module being livepatched is supported or not
    if utils.check_module_unsupported(utils.ARCH, mod_path):
        logging.warning("%s (%s): Module %s is not supported by SLE",
                        cs.full_cs_name(), cs.kernel, mod)

    cs.modules[mod] = str(mod_path)


def __setup_check_syms(cs, mod, syms, arch):
    # Verify if the functions exist in the specified object
    arch_syms = cs.check_symbol_archs(arch, mod, syms, False)
    for arch, syms in arch_syms.items():
        logging.warning("%s-%s (%s): Symbols %s not found on %s object",
                        cs.full_cs_name(), arch, cs.kernel,
                        ",".join(syms), mod)

