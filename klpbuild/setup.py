# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import json
import logging
import platform
import re
from collections import OrderedDict
from pathlib import Path
import sys

import requests
from natsort import natsorted

from klpbuild import utils
from klpbuild.config import Config
from klpbuild.ibs import IBS
from klpbuild.ksrc import GitHelper
from klpbuild.codestream import Codestream


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

        if not self.kdir and not self.host and not lp_name.startswith("bsc"):
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

    # Parse SLE15-SP2_Update_25 to 15.2u25
    @staticmethod
    def parse_cs_line(cs):
        rt = "rt" if "-RT" in cs else ""

        sle, _, u = cs.replace("SLE", "").replace("-RT", "").split("_")
        if "-SP" in sle:
            sle, sp = sle.split("-SP")
        else:
            sle, sp = sle, "0"

        return int(sle), int(sp), int(u), rt

    @staticmethod
    def download_supported_file():
        logging.info("Downloading codestreams file")
        cs_url = "https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv"
        suse_cert = Path("/etc/ssl/certs/SUSE_Trust_Root.pem")
        if suse_cert.exists():
            req = requests.get(cs_url, verify=suse_cert)
        else:
            req = requests.get(cs_url)

        # exit on error
        req.raise_for_status()

        first_line = True
        codestreams = []
        for line in req.iter_lines():
            # skip empty lines
            if not line:
                continue

            # skip file header
            if first_line:
                first_line = False
                continue

            # remove the last two columns, which are dates of the line
            # and add a fifth field with the forth one + rpm- prefix, and
            # remove the build counter number
            full_cs, proj, kernel_full, _, _ = line.decode("utf-8").strip().split(",")
            kernel = re.sub(r"\.\d+$", "", kernel_full)

            # Fill the majority of possible fields here
            sle, sp, u, rt = Setup.parse_cs_line(full_cs)
            codestreams.append(Codestream(sle, sp, u, rt, proj, kernel))

        return codestreams

    def cs_is_affected(self, cs):
        # We can only check if the cs is affected or not if the CVE was informed
        # (so we can get all commits related to that specific CVE). Otherwise we
        # consider all codestreams as affected.
        if not self.conf.get("cve", ""):
            return True

        sle, sp, up, rt = self.get_cs_tuple(cs)

        to_check = f"{sle}.{sp}"
        if rt:
            to_check = f"{sle}.{sp}rt"

        return len(self.conf["commits"][to_check]["commits"]) > 0

    # Needs to be called after setup_codestreams since the workincs_cs is set
    # there
    def download_missing_cs_data(self):
        data_missing = {}

        for cs, data in self.working_cs.items():
            if self.missing_codestream(cs):
                data_missing[cs] = data

        # Found missing cs data, downloading and extract
        if data_missing:
            logging.info("Download the necessary data from the following codestreams:")
            logging.info(f'\t{" ".join(data_missing.keys())}\n')
            ibs = IBS(self.lp_name, self.filter, self.working_cs)
            ibs.download_cs_data(data_missing)
            logging.info("Done.")

    def setup_codestreams(self):
        # Always get the latest supported.csv file and check the content
        # against the codestreams informed by the user
        all_codestreams = Setup.download_supported_file()

        ksrc = GitHelper(self.lp_name, self.filter, self.data)

        # Called at this point because codestreams is populated
        self.conf["commits"] = ksrc.get_commits(self.conf.get("cve", ""))

        patched_kernels = ksrc.get_patched_kernels(all_codestreams,
                                                   self.conf["commits"],
                                                   self.conf.get("cve", ""))

        self.conf["patched_kernels"] = patched_kernels

        # list of codestreams that matches the file-funcs argument
        self.working_cs = OrderedDict()
        patched_cs = []
        unaffected_cs = []

        if self.no_check:
            logging.info("Option --no-check was specified, checking all codestreams that are not filtered out...")

        for cs in all_codestreams:
            # Only process codestreams that are related to the argument
            if not re.match(self.codestream, cs.name()):
                continue

            # Skip patched codestreams
            if not self.no_check:
                if cs.kernel in patched_kernels:
                    patched_cs.append(cs)
                    continue

                if not self.cs_is_affected(cs):
                    unaffected_cs.append(cs)
                    continue

            # Set supported archs for the codestream
            # RT is supported only on x86_64 at the moment
            archs = ["x86_64"]
            if not cs.rt:
                archs.extend(["ppc64le", "s390x"])

            cs.set_archs(archs)
            self.working_cs[cs.name()] = cs.data()

        if patched_cs:
            cs_list = utils.classify_codestreams(patched_cs)
            logging.info("Skipping already patched codestreams:")
            logging.info(f'\t{" ".join(cs_list)}')

        if unaffected_cs:
            cs_list = utils.classify_codestreams(unaffected_cs)
            logging.info("Skipping unaffected codestreams (missing backports):")
            logging.info(f'\t{" ".join(cs_list)}')

        # Add new codestreams to the already existing list, skipping duplicates
        self.conf["patched_cs"] = natsorted(list(set(self.conf.get("patched_cs", []) + patched_cs)))

        # working_cs will contain the final dict of codestreams that wast set
        # by the user, avoid downloading missing codestreams that are not affected
        self.working_cs = self.filter_cs(self.working_cs, verbose=True)

        if not self.working_cs.keys():
            logging.info("All supported codestreams are already patched. Exiting klp-build")
            sys.exit(0)

        logging.info("All affected codestreams:")
        cs_list = utils.classify_codestreams(self.working_cs.keys())
        logging.info(f'\t{" ".join(cs_list)}')


    def setup_project_files(self):
        self.lp_path.mkdir(exist_ok=True)

        # When kdir is used, the only supported architecture is the HOST
        # architecture.
        if self.kdir or self.host:
            self.working_cs["linux"] = {
                "kernel": platform.uname()[2].replace("-default", ""),
                "modules": {},
                "files": self.file_funcs,
                "archs": [utils.ARCH],
            }
        else:
            self.setup_codestreams()

        logging.info(f"Affected architectures:")
        logging.info(f"\t{' '.join(self.conf['archs'])}")

        self.download_missing_cs_data()

        logging.info("Checking files, symbols, modules...")
        # Setup the missing codestream info needed
        for cs, data in self.working_cs.items():
            data["files"] = copy.deepcopy(self.file_funcs)

            # Check if the files exist in the respective codestream directories
            mod_syms = {}
            kernel = self.get_cs_kernel(cs)
            for f, fdata in data["files"].items():

                self.validate_config(cs, fdata["conf"], fdata["module"])

                sdir = self.get_sdir(cs)
                if not Path(sdir, f).is_file():
                    raise RuntimeError(f"{cs} ({kernel}): File {f} not found on {str(sdir)}")

                ipa_f = self.get_ipa_file(cs, f)
                if not ipa_f.is_file():
                    msg = f"{cs} ({kernel}): File {ipa_f} not found."
                    if not self.kdir and not self.host:
                        msg += " Creating an empty file."
                        ipa_f.touch()
                    logging.warning(msg)

                # If the config was enabled on all supported architectures,
                # there is no point in leaving the conf being set, since the
                # feature will be available everywhere.
                if self.conf["archs"] == utils.ARCHS:
                    fdata["conf"] = ""

                mod = fdata["module"]
                if not data["modules"].get(mod, ""):
                    if self.is_mod(mod):
                        mod_path = str(self.find_module_obj(utils.ARCH, cs, mod,
                                                            check_support=True))
                    else:
                        mod_path = str(self.get_kernel_path(utils.ARCH, cs))

                    data["modules"][mod] = mod_path

                mod_syms.setdefault(mod, [])
                mod_syms[mod].extend(fdata["symbols"])

            # Verify if the functions exist in the specified object
            for mod, syms in mod_syms.items():
                arch_syms = self.check_symbol_archs(cs, mod, syms, False)
                if arch_syms:
                    for arch, syms in arch_syms.items():
                        m_syms = ",".join(syms)
                        cs_ = f"{cs}-{arch} ({self.get_cs_kernel(cs)})"
                        logging.warning(f"{cs_}: Symbols {m_syms} not found on {mod} object")

        # Update and save codestreams data
        for cs, data in self.working_cs.items():
            self.codestreams[cs] = data

        self.flush_cs_file()

        # cpp will use this data in the next step
        with open(self.conf_file, "w") as f:
            f.write(json.dumps(self.conf, indent=4))

        logging.info("Done. Setup finished.")
