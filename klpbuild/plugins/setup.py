# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import logging
from pathlib import Path
from natsort import natsorted

from klpbuild.klplib import utils
from klpbuild.klplib.codestreams_data import get_codestreams_data, set_codestreams_data, store_codestreams
from klpbuild.klplib.ksrc import GitHelper
from klpbuild.klplib.templ import generate_commit_msg_file

from klpbuild.plugins.scan import scan


class Setup():
    def __init__(
        self,
        lp_name,
    ):

        lp_path = utils.get_workdir(lp_name)
        if lp_path.exists() and not lp_path.is_dir():
            raise ValueError("--name needs to be a directory, or not to exist")
        self.lp_name = lp_name

    @staticmethod
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

    def setup_codestreams(self, data):
        if not self.lp_name.startswith("bsc"):
            raise ValueError("Please use prefix 'bsc' when creating a livepatch for codestreams")

        # Called at this point because codestreams is populated
        # FIXME: we should check all configs, like when using --conf-mod-file-funcs
        commits, patched_cs, patched_kernels, codestreams = scan(data["cve"],
                                                                 data["conf"],
                                                                 data["no_check"],
                                                                 data["lp_filter"],
                                                                 utils.get_workdir(self.lp_name))
        # Add new codestreams to the already existing list, skipping duplicates
        old_patched_cs = get_codestreams_data('patched_cs')
        new_patched_cs = natsorted(list(set(old_patched_cs + patched_cs)))

        set_codestreams_data(commits=commits, patched_kernels=patched_kernels,
                             patched_cs=new_patched_cs, cve=data['cve'])
        return codestreams

    def setup_project_files(self, codestreams, ffuncs, archs):
        utils.get_workdir(self.lp_name).mkdir(exist_ok=True)

        archs.sort()
        set_codestreams_data(archs=archs)

        logging.info("Affected architectures:")
        logging.info("\t%s", ' '.join(archs))

        generate_commit_msg_file(self.lp_name)

        logging.info("Checking files, symbols, modules...")
        # Setup the missing codestream info needed
        for cs in codestreams:
            cs.set_files(copy.deepcopy(ffuncs))

            # Check if the files exist in the respective codestream directories
            mod_syms = {}
            for f, fdata in cs.files.items():

                mod = fdata["module"]
                cs.validate_config(fdata["conf"], mod)

                sdir = cs.get_src_dir()
                if not Path(sdir, f).is_file():
                    raise RuntimeError(f"{cs.name()} ({cs.kernel}): File {f} not found on {str(sdir)}")

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

        store_codestreams(self.lp_name, codestreams)
        logging.info("Done. Setup finished.")
