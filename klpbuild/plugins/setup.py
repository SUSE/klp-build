# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import logging

from natsort import natsorted

from klpbuild.klplib import bugzilla, utils
from klpbuild.klplib.cmd import add_arg_lp_filter, add_arg_lp_name
from klpbuild.klplib.codestreams_data import (
    get_codestreams_data,
    set_codestreams_data,
    store_codestreams,
)
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.templ import generate_commit_msg_file
from klpbuild.plugins.scan import scan

PLUGIN_CMD = "setup"


def register_argparser(subparser):
    args = subparser.add_parser(
        PLUGIN_CMD, help="Establish an initial working directory for a given livepatch"
    )
    add_arg_lp_name(args)
    add_arg_lp_filter(args)
    args.add_argument("--cve", type=str, required=False, help="The CVE assigned to this livepatch")
    args.add_argument("--conf", type=str, required=False, help="The kernel CONFIG used to be build the livepatch")
    args.add_argument(
        "--no-check",
        action="store_true",
        help="Do not check for already patched codestreams, do the setup for all non filtered codestreams.",
    )
    args.add_argument(
        "--full-checks",
        action="store_true",
        help="Enable advanced checks that verify if symbol can be livepatched. "
        "Enabling this option can incur in severe slowdowns.",
    )
    args.add_argument(
        "--file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="File and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs file/path.c func1 "
        "func2 --file-func file/patch2 func1...",
    )
    args.add_argument(
        "--mod-file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="Module, file and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs module1 file/path.c func1 "
        "func2 --file-func module2 file/patch2 func1...",
    )
    args.add_argument(
        "--conf-mod-file-funcs",
        required=False,
        action="append",
        nargs="*",
        default=[],
        help="Conf, module, file and functions to be livepatched. Can be set "
        "multiple times. The format is --file-funcs conf1 module1 file/path.c func1 "
        "func2 --file-func conf2 module2 file/patch2 func1...",
    )
    args.add_argument(
        "--module", type=str, default="vmlinux", help="The module that will be livepatched for all files"
    )
    args.add_argument(
        "--archs",
        default=utils.ARCHS,
        choices=utils.ARCHS,
        nargs="+",
        help="Supported architectures for this livepatch",
    )
    args.add_argument(
        "--add-patches",
        type=str,
        nargs="+",
        required=False,
        default=[],
        help="Path(s) of additional patches from kernel-source (e.g. "
        "patches.suse/some-fix.patch). Can specify multiple patches. "
        "These patches will be checked per-codestream and applied "
        "before CVE patches if missing.",
    )


def run(lp_name, lp_filter, no_check, archs, cve, conf, module, file_funcs,
        mod_file_funcs, conf_mod_file_funcs, full_checks, add_patches=None):
    if add_patches is None:
        add_patches = []

    codestreams = setup_codestreams(lp_name, {"cve": cve, "conf": conf,
                                              "lp_filter": lp_filter,
                                              "no_check": no_check,
                                              "archs": archs,
                                              "extra_patches": add_patches})

    if conf:
        setup_manual(codestreams, archs, conf, module,
                     file_funcs, mod_file_funcs,
                     conf_mod_file_funcs)

    setup_archs(codestreams)
    setup_project_files(lp_name, codestreams, full_checks)


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

    # Inspect which codestreams are enabled for the affected architectures
    for cs in codestreams:
        cs.archs = (cs.archs & set(utils.affected_archs([cs])))


def setup_codestreams(lp_name, data):
    utils.validate_lp_name(lp_name)

    # Called at this point because codestreams is populated
    if data["no_check"]:
        logging.info("Option --no-check was specified, checking all codestreams that are not filtered out...")
        upstream = []
        patched_cs = []
        all_codestreams = get_supported_codestreams()
        codestreams = utils.filter_codestreams(data["lp_filter"], all_codestreams)
    else:
        if not (cve := data["cve"]):
            cve = bugzilla.get_bug_cve(bugzilla.get_bug(lp_name))
            assert cve, f"Could not retrieve CVE from bugzilla for {lp_name}"
            logging.info("CVE retrieved from bugzilla: %s", cve)
            data["cve"] = cve

        _, upstream, patched_cs, codestreams = scan(data["cve"], data["conf"],
                                                    data["lp_filter"], True,
                                                    data["archs"],
                                                    utils.get_workdir(lp_name),
                                                    data.get("extra_patches", []))

    # Add new codestreams names to the already existing list, skipping
    # duplicates
    patched_cs = [cs.full_cs_name() for cs in patched_cs]
    old_patched_cs = get_codestreams_data('patched_cs')
    new_patched_cs = natsorted(list(set(old_patched_cs + patched_cs)))

    set_codestreams_data(upstream=upstream, patched_cs=new_patched_cs,
                         cve=data['cve'])
    return codestreams


def setup_project_files(lp_name, codestreams, full_checks):
    utils.get_workdir(lp_name).mkdir(exist_ok=True)

    generate_commit_msg_file(lp_name)

    if codestreams:
        logging.info("Checking files, symbols, modules...")

    # Setup the missing codestream info needed
    for cs in codestreams:
        syms_to_be_checked = {}

        # Check if the files and symbols exist in the respective codestream directories
        for f, fdata in cs.files.copy().items():
            conf = fdata["conf"]
            archs = cs.configs[conf]
            syms = fdata["symbols"]
            if not syms:
                logging.warning("%s (%s): No symbols found for %s file."
                                " Skipping.", cs.full_cs_name(), cs.kernel, f)
                cs.files.pop(f)
                continue

            __setup_check_file(cs, f)

            # FIXME: sorted() is needed here so that x86_64 comes as the first
            # arch in the loop and __setup_check_mode only check that one. This
            # is a nasty workaround required until cs.modules and cs.configs
            # get reworked to store per-arch values.
            for arch in sorted(archs, reverse=True):
                mod = cs.get_file_mod(f, arch)
                __setup_check_mod(cs, mod, arch)

            # append the current symbols and module to anuy previously set ones
            mod_info = syms_to_be_checked.get(mod, {})
            syms_to_be_checked[mod] = {
                "syms": mod_info.get("syms", []) + syms,
                "archs": mod_info.get("archs", []) + list(archs.keys()),
            }

        # Just call the symbol check once per module
        # The set calls are necessary because we can have duplicated entries
        # like the arch for different files.
        for mod, mod_info in syms_to_be_checked.items():
            __symbol_check(cs, mod, set(mod_info["syms"]), set(mod_info["archs"]), full_checks)

        if not cs.files:
            logging.error(f"%s (%s): No files eligible to be livepatched.", cs.full_cs_name(), cs.kernel)
            logging.error(f"Try using --file-funcs to specify the affected file and function.")
            exit(1)

    store_codestreams(lp_name, codestreams)
    logging.info("Done. Setup finished.")


def __setup_check_file(cs, file):
    if not cs.check_file_exists(file):
        raise RuntimeError(f"{cs.full_cs_name()} ({cs.kernel}): File {file} not found.")

    # Get the first affected arch
    ipa_f = cs.get_ipa_file(file)
    if not ipa_f.is_file():
        ipa_f.touch()
        logging.warning("%s (%s): File %s not found. Creating an empty file.",
                        cs.full_cs_name(), cs.kernel, ipa_f)


def __setup_check_mod(cs, mod, arch):
    if mod in cs.modules:
        return

    mod_path = cs.find_obj_path(arch, mod)

    # Validate if the module being livepatched is supported or not
    if utils.check_module_unsupported(arch, mod_path):
        logging.warning("%s (%s): Module %s is not supported by SLE",
                        cs.full_cs_name(), cs.kernel, mod)

    cs.modules[mod] = str(mod_path)


def __symbol_check(cs, mod, syms, archs, full_checks):
    """
    Check if a given symbol is inlined on all architectures. If yes, it means
    that the klp-ccp can figure it our the callers, and automatically bring
    them to the livepatch. Otherwise, it can mean that a given symbol had
    different inlining decisions on different architectures, which is why a
    warning is shown.
    """

    mod_syms = {}
    for arch in archs:
        # Verify if the functions exist in the specified object
        mod_syms.update(cs.check_symbol_archs(arch, mod, syms, False, full_checks))

    # Reverse the dict, checking in which architectures are the symbol is not
    # present. It it's not found on all architectures, it can mean that it's
    # inline in all of them, so it's mostly harmless, since klp-ccp can handle
    # it.
    sym_archs = {}
    for larch, lsyms in mod_syms.items():
        for sym in lsyms:
            sym_archs.setdefault(sym, [])
            sym_archs[sym].append(larch)

    for sym, larchs in sym_archs.items():
        # The missing symbol can be a problem is it's missing on some
        # architectures and present in others.
        if set(larchs) != archs:
            logging.warning(
                "%s-%s (%s): Symbols %s not found on %s object",
                cs.full_cs_name(),
                str(larchs),
                cs.kernel,
                sym,
                mod,
            )
