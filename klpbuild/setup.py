# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import logging
import re
from pathlib import Path

from natsort import natsorted

from klpbuild import utils
from klpbuild.config import Config
from klpbuild.ksrc import GitHelper


class Setup(Config):
    def __init__(
        self,
        lp_name,
        lp_filter,
        file_funcs,
        mod_file_funcs,
        conf_mod_file_funcs,
        mod_arg,
        conf,
        skips,
    ):
        super().__init__(lp_name)

        if not lp_name.startswith("bsc"):
            raise ValueError("Please use prefix 'bsc' when creating a livepatch for codestreams")

        if conf and not conf.startswith("CONFIG_"):
            raise ValueError("Please specify --conf with CONFIG_ prefix")

        if self.lp_path.exists() and not self.lp_path.is_dir():
            raise ValueError("--name needs to be a directory, or not to exist")

        if not file_funcs and not mod_file_funcs and not conf_mod_file_funcs:
            raise ValueError("You need to specify at least one of the file-funcs variants!")

        self.lp_name = lp_name
        self.lp_filter = lp_filter
        self.lp_skips = skips
        self.conf = conf
        self.file_funcs = {}

        for f in file_funcs:
            filepath = f[0]
            funcs = f[1:]

            self.file_funcs[filepath] = {"module": mod_arg, "conf": conf, "symbols": funcs}

        for f in mod_file_funcs:
            fmod = f[0]
            filepath = f[1]
            funcs = f[2:]

            self.file_funcs[filepath] = {"module": fmod, "conf": conf, "symbols": funcs}

        for f in conf_mod_file_funcs:
            fconf = f[0]
            fmod = f[1]
            filepath = f[2]
            funcs = f[3:]

            self.file_funcs[filepath] = {"module": fmod, "conf": fconf, "symbols": funcs}

    def setup_codestreams(self, cve, no_check):
        ksrc = GitHelper(self.lp_name, self.lp_filter, self.lp_skips)

        if cve:
            cve = re.search(r"([0-9]+\-[0-9]+)", cve).group(1)

        # Called at this point because codestreams is populated
        # FIXME: we should check all configs, like when using --conf-mod-file-funcs
        commits, patched_cs, patched_kernels, codestreams = ksrc.scan(cve,
                                                                      self.conf,
                                                                      no_check)
        self.cs_data.commits = commits
        self.cs_data.patched_kernels = patched_kernels
        # Add new codestreams to the already existing list, skipping duplicates
        self.cs_data.patched_cs = natsorted(list(set(self.cs_data.patched_cs + patched_cs)))

        return codestreams

    def setup_project_files(self, cve, archs, no_check):
        self.lp_path.mkdir(exist_ok=True)

        codestreams = self.setup_codestreams(cve, no_check)
        archs = archs.sort()

        logging.info("Affected architectures:")
        logging.info("\t%s", ' '.join(archs))

        logging.info("Checking files, symbols, modules...")
        # Setup the missing codestream info needed
        for cs in codestreams:
            cs.set_files(copy.deepcopy(self.file_funcs))

            # Check if the files exist in the respective codestream directories
            mod_syms = {}
            for f, fdata in cs.files.items():

                mod = fdata["module"]
                cs.validate_config(fdata["conf"], mod)

                sdir = cs.get_sdir()
                if not Path(sdir, f).is_file():
                    raise RuntimeError(f"{cs.name()} ({cs.kernel}): File {f} not found on {str(sdir)}")

                ipa_f = cs.get_ipa_file(f)
                if not ipa_f.is_file():
                    msg = f"{cs.name()} ({cs.kernel}): File {ipa_f} not found. Creating an empty file."
                    ipa_f.touch()
                    logging.warning(msg)

                # If the config was enabled on all supported architectures,
                # there is no point in leaving the conf being set, since the
                # feature will be available everywhere.
                if archs == utils.ARCHS:
                    fdata["conf"] = ""

                mod_path = cs.find_obj_path(utils.ARCH, mod)

                # Validate if the module being livepatches is supported or not
                if utils.check_module_unsupported(mod_path):
                    logging.warning("%s (%s}): Module %s is not supported by SLE", cs.name(), cs.kernel, mod)

                cs.modules[mod] = str(mod_path)
                mod_syms.setdefault(mod, [])
                mod_syms[mod].extend(fdata["symbols"])

            # Verify if the functions exist in the specified object
            for mod, syms in mod_syms.items():
                arch_syms = cs.check_symbol_archs(archs, mod, syms, False)
                if arch_syms:
                    for arch, syms in arch_syms.items():
                        m_syms = ",".join(syms)
                        cs_ = f"{cs.name()}-{arch} ({cs.kernel})"
                        logging.warning("%s: Symbols %s not found on %s object", cs_, m_syms, mod)

        self.flush_cs_file(codestreams)
        logging.info("Done. Setup finished.")
