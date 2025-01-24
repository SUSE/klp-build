# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import configparser
import dataclasses
import json
import logging
import os
from collections import OrderedDict
from pathlib import Path, PurePath
from natsort import natsorted

from klpbuild.klplib.codestream import Codestream


@dataclasses.dataclass
class CodestreamData:
    cve: str
    archs: list[str]
    patched_kernels: list[str]
    patched_cs: list[str]
    commits: dict[str, str]


class Config:
    def __init__(self, lp_name):
        # FIXME: Config is instantiated multiple times, meaning that the
        # config file gets loaded and the logs are printed as many times.

        logging.basicConfig(level=logging.INFO, format="%(message)s")

        home = Path.home()
        self.user_conf_file = Path(home, ".config/klp-build/config")
        if not self.user_conf_file.is_file():
            logging.warning("Warning: user configuration file not found")
            # If there's no configuration file assume fresh install.
            # Prepare the system with a default environment and conf.
            self.setup_user_env(Path(home, "klp"))

        self.load_user_conf()

        self.codestreams = OrderedDict()
        self.data = self.get_user_path('data_dir')
        self.lp_path = Path(self.get_user_path('work_dir'), lp_name)

        self.cs_data = CodestreamData("", [], [], [], {})
        self.cs_file = Path(self.lp_path, "codestreams.json")
        if self.cs_file.is_file():
            with open(self.cs_file) as f:
                jfile = json.loads(f.read(), object_pairs_hook=OrderedDict)
                self.cs_data = CodestreamData(cve=jfile["cve"],
                                              archs=jfile["archs"],
                                              patched_kernels=jfile["patched_kernels"],
                                              patched_cs=jfile["patched_cs"],
                                              commits=jfile["commits"])
                json_cs = jfile["codestreams"]
                # Sorte the codestreams before inserting in the OrderedDict
                for cs in natsorted(json_cs.keys()):
                    self.codestreams[cs] = Codestream.from_data(json_cs[cs])


    def setup_user_env(self, basedir):
        workdir = Path(basedir, "livepatches")
        datadir = Path(basedir, "data")

        config = configparser.ConfigParser(allow_no_value=True)

        config['Paths'] = {'work_dir': workdir,
                           'data_dir': datadir,
                           '## SUSE internal use only ##': None,
                           '#kgr_patches_dir': 'kgraft-patches/',
                           '#kgr_patches_tests_dir': 'kgraft-patches_testscripts/',
                           '#kernel_src_dir': 'kernel-src/'}

        config['Settings'] = {'workers': 4}

        logging.info("Creating default user configuration: '%s'", self.user_conf_file)
        os.makedirs(os.path.dirname(self.user_conf_file), exist_ok=True)
        with open(self.user_conf_file, 'w') as f:
            config.write(f)

        os.makedirs(workdir, exist_ok=True)
        os.makedirs(datadir, exist_ok=True)

    def load_user_conf(self):
        config = configparser.ConfigParser()
        logging.info("Loading user configuration from '%s'", self.user_conf_file)
        config.read(self.user_conf_file)

        # Check mandatory fields
        for s in ['Paths', 'Settings']:
            if s not in config:
                raise ValueError(f"config: '{s}' section not found")

        self.user_conf = config

    def get_user_path(self, entry, isdir=True, isopt=False):
        if entry not in self.user_conf['Paths']:
            if isopt:
                return ""
            raise ValueError(f"config: '{entry}' entry not found")

        p = Path(self.user_conf['Paths'][entry])
        if not p.exists():
            raise ValueError(f"'{p}' file or directory not found")
        if isdir and not p.is_dir():
            raise ValueError("{p} should be a directory")
        if not isdir and not p.is_file():
            raise ValueError("{p} should be a file")

        return p

    def get_user_settings(self, entry, isopt=False):
        if entry not in self.user_conf['Settings']:
            if isopt:
                return ""
            raise ValueError(f"config: '{entry}' entry not found")

        return self.user_conf['Settings'][entry]


    def get_tests_path(self, lp_name):
        kgr_path = self.get_user_path('kgr_patches_tests_dir')

        test_sh = Path(kgr_path, f"{lp_name}_test_script.sh")
        if test_sh.is_file():
            return test_sh

        test_dir_sh = Path(kgr_path, f"{lp_name}/test_script.sh")
        if test_dir_sh.is_file():
            # For more complex tests we support using a directory containing
            # as much files as needed. A `test_script.sh` is still required
            # as an entry point.
            return PurePath(test_dir_sh).parent

        raise RuntimeError(f"Couldn't find {test_sh} or {test_dir_sh}")


    # Update and save codestreams data, working_cs is always a list
    def flush_cs_file(self, working_cs):
        # Update the latest state of the codestreams
        for cs in working_cs:
            self.codestreams[cs.name()] = cs

        # Format each codestream for the json
        cs_data = {}
        for key, cs in self.codestreams.items():
            cs_data[key] = cs.data()

        data = {"archs": self.cs_data.archs,
                "commits": self.cs_data.commits,
                "cve": self.cs_data.cve,
                "patched_cs": self.cs_data.patched_cs,
                "patched_kernels": self.cs_data.patched_kernels,
                "codestreams": cs_data}

        with open(self.cs_file, "w") as f:
            f.write(json.dumps(data, indent=4))
