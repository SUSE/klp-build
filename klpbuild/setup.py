# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import json
import logging
import platform
import re
from collections import OrderedDict
from pathlib import Path

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
        kdir,
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
    ):
        super().__init__(lp_name, lp_filter, kdir, data_dir, skips=skips)

        archs.sort()

        if conf and not conf.startswith("CONFIG_"):
            raise ValueError("Please specify --conf with CONFIG_ prefix")

        if self.lp_path.exists() and not self.lp_path.is_dir():
            raise ValueError("--bsc needs to be a directory, or not to exist")

        if not file_funcs and not mod_file_funcs and not conf_mod_file_funcs:
            raise ValueError("You need to specify at least one of the file-funcs variants!")

        self.conf["archs"] = archs
        self.conf["cve"] = re.search(r"([0-9]+\-[0-9]+)", cve).group(1)

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
    def parse_cs_line(self, cs):
        rt = "rt" if "-RT" in cs else ""

        sle, _, u = cs.replace("SLE", "").replace("-RT", "").split("_")
        if "-SP" in sle:
            sle, sp = sle.split("-SP")
        else:
            sle, sp = sle, "0"

        return int(sle), int(sp), int(u), rt

    def download_supported_file(self):
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
        codestreams = OrderedDict()
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
            sle, sp, u, rt = self.parse_cs_line(full_cs)
            if rt:
                cs_key = f"{sle}.{sp}{rt}u{u}"
            else:
                cs_key = f"{sle}.{sp}u{u}"

            codestreams[cs_key] = {
                "project": proj,
                "kernel": kernel,
                "build-counter": kernel_full[-1],
                "branch": "",
                "sle": sle,
                "sp": sp,
                "update": u,
                "modules": {},
            }

            if rt:
                codestreams[cs_key]["rt"] = True

        return codestreams

    def cs_repo(self, cs):
        sle, sp, up, rt = self.get_cs_tuple(cs)
        if up == 0:
            return "standard"

        repo = f"SUSE_SLE-{sle}"
        if sp != 0:
            repo = f"{repo}-SP{sp}"

        repo = f"{repo}_Update"

        # On 15.5 the RT kernels and in the main codestreams
        if not rt or (sle >= 15 and sp >= 5):
            return repo

        return f"{repo}_Products_SLERT_Update"

    # s390x is enabled on 12.5 for all updates.
    # s390x is not supported on 15.1
    # s390x is supported from 15.2 onwards.
    def is_s390_supported(self, cs):
        sle, sp, _, _ = self.get_cs_tuple(cs)
        return sle == 12 or (sle == 15 and sp >= 2)

    def setup_codestreams(self):
        # Always get the latest supported.csv file and check the content
        # against the codestreams informed by the user
        all_codestreams = self.download_supported_file()

        ksrc = GitHelper(self.lp_name, self.filter, self.kdir, self.data)

        # Called at this point because codestreams is populated
        self.conf["commits"] = ksrc.get_commits(self.conf["cve"])

        # do not get the commits twice
        patched_kernels = self.conf.get("patched_kernels", [])
        if not patched_kernels:
            patched_kernels = ksrc.get_patched_kernels(self.conf["commits"])

        self.conf["patched_kernels"] = patched_kernels

        cs_data_missing = {}

        # list of codestreams that matches the file-funcs argument
        self.working_cs = OrderedDict()
        patched_cs = []

        for cs, data in all_codestreams.items():
            # Only process codestreams that are related to the argument
            if not re.match(self.codestream, cs):
                continue

            # Skip patched codestreams
            if data["kernel"] in patched_kernels:
                patched_cs.append(cs)
                continue

            data["files"] = self.file_funcs
            data["repo"] = self.cs_repo(cs)

            # Set supported archs for the codestream
            # RT is supported only on x86_64 at the moment
            archs = ["x86_64"]
            if not data.get("rt", False):
                archs.append("ppc64le")

                if self.is_s390_supported(cs):
                    archs.append("s390x")

            data["archs"] = archs

            self.working_cs[cs] = data

            if self.missing_codestream(cs):
                cs_data_missing[cs] = data

        if patched_cs:
            cs_list = utils.classify_codestreams(patched_cs)
            logging.info("Skipping already patched codestreams:")
            logging.info(f'\t{" ".join(cs_list)}')

        # Add new codestreams to the already existing list, skipping duplicates
        self.conf["patched_cs"] = natsorted(list(set(self.conf.get("patched_cs", []) + patched_cs)))

        # working_cs will contain the final dict of codestreams that wast set
        # by the user, avoid downloading missing codestreams that are not affected
        self.working_cs = self.filter_cs(self.working_cs, verbose=True)

        # Remove filtered codestreams from missing data codestreams, as we don't
        # need to download data from codestreams that we don't need to build
        # livepatched
        data_missing = cs_data_missing.copy()
        for cs in cs_data_missing.keys():
            if cs not in self.working_cs.keys():
                data_missing.pop(cs)

        # Found missing cs data, downloading and extract
        if data_missing:
            logging.info("Download the necessary data from the following codestreams:")
            logging.info(f'\t{" ".join(data_missing.keys())}\n')
            ibs = IBS(self.lp_name, self.filter, self.working_cs)
            ibs.download_cs_data(data_missing)

        logging.info("All affected codestreams:")
        cs_list = utils.classify_codestreams(self.working_cs.keys())
        logging.info(f'\t{" ".join(cs_list)}')

    def setup_project_files(self):
        self.lp_path.mkdir(exist_ok=True)

        # When kdir is used, the only supported architecture is the HOST
        # architecture.
        if self.kdir:
            self.working_cs["linux"] = {
                "kernel": platform.uname()[2],
                "modules": {},
                "files": self.file_funcs,
                "archs": [utils.ARCH]
            }
        else:
            self.setup_codestreams()

        # Setup the missing codestream info needed
        for cs, data in self.working_cs.items():
            # Check if the files exist in the respective codestream directories
            mod_syms = {}
            for f, fdata in data["files"].items():
                if not Path(self.get_sdir(cs), f).is_file():
                    raise RuntimeError(f"{cs}: File {f} not found")

                ipa_f = self.get_ipa_file(cs, f)
                if not ipa_f.is_file():
                    msg = f"{cs}: File {ipa_f} not found."
                    if not self.kdir:
                        msg += " Creating an empty file."
                        ipa_f.touch()
                    logging.warning(msg)

                # Check if the CONFIG is enabled on all affected architectures
                self.validate_config(cs, fdata["conf"])

                # If the config was enabled on all supported architectures,
                # there is no point in leaving the conf being set, since the
                # feature will be available everywhere.
                if self.conf["archs"] == utils.ARCHS:
                    fdata["conf"] = ""

                mod = fdata["module"]
                if not data["modules"].get(mod, ""):
                    data["modules"][mod] = self.find_module_obj(utils.ARCH, cs, mod, check_support=True)

                mod_syms.setdefault(mod, [])
                mod_syms[mod].extend(fdata["symbols"])

            # Verify if the functions exist in the specified object
            for mod, syms in mod_syms.items():
                arch_syms = self.check_symbol_archs(cs, mod, syms, False)
                if arch_syms:
                    for arch, syms in arch_syms.items():
                        logging.warning(f'{cs}({arch}): Symbols {",".join(syms)} not found on {mod} object')

        # Update and save codestreams data
        for cs, data in self.working_cs.items():
            self.codestreams[cs] = data

        self.flush_cs_file()

        # cpp will use this data in the next step
        with open(self.conf_file, "w") as f:
            f.write(json.dumps(self.conf, indent=4))
