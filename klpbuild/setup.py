# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import json
import logging
import platform
import re
from pathlib import Path
import sys

import requests
from natsort import natsorted

from klpbuild import utils
from klpbuild.config import Config
from klpbuild.ibs import IBS
from klpbuild.ksrc import GitHelper


class Setup(Config):
    def __init__(
        self,
        lp_name,
        lp_filter,
        data_dir,
        cve,
        cs_arg,
        file_funcs,
        mod_file_funcs,
        conf_mod_file_funcs,
        mod_arg,
        conf,
        archs,
        skips,
        no_check,
    ):
        super().__init__(lp_name, lp_filter, data_dir, skips=skips)

        archs.sort()

        if not lp_name.startswith("bsc"):
            raise ValueError("Please use prefix 'bsc' when creating a livepatch for codestreams")

        if conf and not conf.startswith("CONFIG_"):
            raise ValueError("Please specify --conf with CONFIG_ prefix")

        if self.lp_path.exists() and not self.lp_path.is_dir():
            raise ValueError("--name needs to be a directory, or not to exist")

        if not file_funcs and not mod_file_funcs and not conf_mod_file_funcs:
            raise ValueError("You need to specify at least one of the file-funcs variants!")

        self.conf["archs"] = archs
        if cve:
            self.conf["cve"] = re.search(r"([0-9]+\-[0-9]+)", cve).group(1)

        self.no_check = no_check
        self.codestream = cs_arg
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

    # Needs to be called after setup_codestreams since the workincs_cs is set
    # there
    def download_missing_cs_data(self):
        data_missing = []
        cs_missing = []

        for cs in self.working_cs:
            if not cs.get_boot_file("config").exists():
                data_missing.append(cs)
                cs_missing.append(cs.name())

        # Found missing cs data, downloading and extract
        if data_missing:
            logging.info("Download the necessary data from the following codestreams:")
            logging.info(f'\t{" ".join(cs_missing)}\n')
            ibs = IBS(self.lp_name, self.filter, {})
            ibs.download_cs_data(data_missing)
            logging.info("Done.")


    def setup_codestreams(self):
        ksrc = GitHelper(self.lp_name, self.filter, skips=self.skips)

        # Called at this point because codestreams is populated
        commits, patched_cs, patched_kernels, self.working_cs = ksrc.scan(
                                                     self.conf.get("cve", ""),
                                                     self.no_check)
        self.conf["commits"] = commits
        self.conf["patched_kernels"] = patched_kernels
        # Add new codestreams to the already existing list, skipping duplicates
        self.conf["patched_cs"] = natsorted(list(set(self.conf.get("patched_cs",
                                                                   []) + patched_cs)))


    def setup_project_files(self):
        self.lp_path.mkdir(exist_ok=True)

        self.setup_codestreams()

        logging.info(f"Affected architectures:")
        logging.info(f"\t{' '.join(self.conf['archs'])}")

        self.download_missing_cs_data()

        logging.info("Checking files, symbols, modules...")
        # Setup the missing codestream info needed
        for cs in self.working_cs:
            cs.set_files(copy.deepcopy(self.file_funcs))

            # Check if the files exist in the respective codestream directories
            mod_syms = {}
            kernel = cs.kernel
            for f, fdata in cs.files.items():

                self.validate_config(cs, fdata["conf"], fdata["module"])

                sdir = cs.get_sdir()
                if not Path(sdir, f).is_file():
                    raise RuntimeError(f"{cs.name()} ({kernel}): File {f} not found on {str(sdir)}")

                ipa_f = cs.get_ipa_file(f)
                if not ipa_f.is_file():
                    msg = f"{cs.name()} ({kernel}): File {ipa_f} not found. Creating an empty file."
                    ipa_f.touch()
                    logging.warning(msg)

                # If the config was enabled on all supported architectures,
                # there is no point in leaving the conf being set, since the
                # feature will be available everywhere.
                if self.conf["archs"] == utils.ARCHS:
                    fdata["conf"] = ""

                mod = fdata["module"]
                if not cs.modules.get(mod, ""):
                    if self.is_mod(mod):
                        mod_path = str(self.find_module_obj(utils.ARCH, cs, mod,
                                                            check_support=True))
                    else:
                        mod_path = str(cs.get_boot_file("vmlinux"))

                    cs.modules[mod] = mod_path

                mod_syms.setdefault(mod, [])
                mod_syms[mod].extend(fdata["symbols"])

            # Verify if the functions exist in the specified object
            for mod, syms in mod_syms.items():
                arch_syms = self.check_symbol_archs(cs, mod, syms, False)
                if arch_syms:
                    for arch, syms in arch_syms.items():
                        m_syms = ",".join(syms)
                        cs_ = f"{cs.name()}-{arch} ({cs.kernel})"
                        logging.warning(f"{cs_}: Symbols {m_syms} not found on {mod} object")

        self.flush_cs_file(self.working_cs)

        # cpp will use this data in the next step
        with open(self.conf_file, "w") as f:
            f.write(json.dumps(self.conf, indent=4))

        logging.info("Done. Setup finished.")
