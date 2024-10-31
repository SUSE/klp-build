# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from pathlib import Path
import re

from klpbuild.utils import ARCH

class Codestream:
    __slots__ = ("data_path", "lp_path", "sle", "sp", "update", "rt", "ktype",
                 "needs_ibt", "project", "kernel", "archs", "files", "modules",
                 "repo")

    def __init__(self, data_path, lp_path, sle, sp, update, rt, project="",
                 kernel="", archs=[], files={}, modules={}):
        self.data_path = data_path
        self.lp_path = lp_path
        self.sle = sle
        self.sp = sp
        self.update = update
        self.rt = rt
        self.ktype = "-rt" if rt else "-default"
        self.needs_ibt = sle > 15 or (sle == 15 and sp >= 6)
        self.project = project
        self.kernel = kernel
        self.archs = archs
        self.files = files
        self.modules = modules
        self.repo = self.get_repo()


    @classmethod
    def from_codestream(cls, data_path, lp_path, cs, proj, kernel):
        # Parse SLE15-SP2_Update_25 to 15.2u25
        rt = "rt" if "-RT" in cs else ""

        sle, _, u = cs.replace("SLE", "").replace("-RT", "").split("_")
        if "-SP" in sle:
            sle, sp = sle.split("-SP")
        else:
            sp = "0"

        return cls(data_path, lp_path, int(sle), int(sp), int(u), rt, proj, kernel)


    @classmethod
    def from_cs(cls, cs):
        match = re.search(r"(\d+)\.(\d+)(rt)?u(\d+)", cs)
        return cls("", "", int(match.group(1)), int(match.group(2)),
                   int(match.group(4)), match.group(3))


    @classmethod
    def from_data(cls, data_path, lp_path, data):
        return cls(data_path, lp_path, data["sle"], data["sp"], data["update"],
                   data["rt"], data["project"], data["kernel"], data["archs"],
                   data["files"], data["modules"])


    def __eq__(self, cs):
        return self.sle == cs.sle and \
                self.sp == cs.sp and \
                self.update == cs.update and \
                self.rt == cs.rt


    def get_data_dir(self, arch):
        # For the SLE usage, it should point to the place where the codestreams
        # are downloaded
        return Path(self.data_path, arch)


    def get_sdir(self, arch=ARCH):
        # Only -rt codestreams have a suffix for source directory
        ktype = self.ktype.replace("-default", "")
        return Path(self.get_data_dir(arch), "usr", "src", f"linux-{self.kernel}{ktype}")


    def get_odir(self):
        return Path(f"{self.get_sdir(ARCH)}-obj", ARCH, self.ktype.replace("-", ""))


    def get_ipa_file(self, fname):
        return Path(self.get_odir(), f"{fname}.000i.ipa-clones")


    def get_boot_file(self, file, arch=ARCH):
        assert file in ["vmlinux", "config", "symvers"]
        return Path(self.get_data_dir(arch), "boot", f"{file}-{self.kname()}")


    def get_repo(self):
        if self.update == 0:
            return "standard"

        repo = f"SUSE_SLE-{self.sle}"
        if self.sp != 0:
            repo = f"{repo}-SP{self.sp}"

        repo = f"{repo}_Update"

        # On 15.5 the RT kernels and in the main codestreams
        if not self.rt or (self.sle == 15 and self.sp == 5):
            return repo

        return f"{repo}_Products_SLERT_Update"


    def set_archs(self, archs):
        self.archs = archs


    def set_files(self, files):
        self.files = files


    def kname(self):
        return self.kernel + self.ktype


    def name(self):
        if self.rt:
            return f"{self.sle}.{self.sp}rtu{self.update}"

        return f"{self.sle}.{self.sp}u{self.update}"


    def dir(self):
        return Path(self.lp_path, "ccp", self.name())


    def lpdir(self):
        return Path(self.lp_path, "ccp", self.name(), "lp")


    def work_dir(self, fname):
        fpath = f'work_{str(fname).replace("/", "_")}'
        return Path(self.dir(), fpath)


    def name_cs(self):
        if self.rt:
            return f"{self.sle}.{self.sp}rt"
        return f"{self.sle}.{self.sp}"


    # Parse 15.2u25 to SLE15-SP2_Update_25
    def name_full(self):
        buf = f"SLE{self.sle}"

        if int(self.sp) > 0:
            buf = f"{buf}-SP{self.sp}"

        if self.rt:
            buf = f"{buf}-RT"

        return f"{buf}_Update_{self.update}"


    # 15.4 onwards we don't have module_mutex, so template generates
    # different code
    def is_mod_mutex(self):
        return self.sle < 15 or (self.sle == 15 and self.sp < 4)


    def get_mod_path(self, arch):
        return Path(self.get_data_dir(arch), "lib", "modules", f"{self.kname()}")


    # Returns the path to the kernel-obj's build dir, used when build testing
    # the generated module
    def get_kernel_build_path(self, arch):
        return Path(self.get_mod_path(arch), "build")


    def get_all_configs(self, conf):
        """
        Get the config value for all supported architectures of a codestream. If
        the configuration is not set the return value will be an empty dict.
        """
        configs = {}

        for arch in self.archs:
            kconf = self.get_boot_file("config", arch)
            with open(kconf) as f:
                match = re.search(rf"{conf}=([ym])", f.read())
                if match:
                    configs[arch] = match.group(1)

        return configs


    def data(self):
        return {
                "sle" : self.sle,
                "sp" : self.sp,
                "update" : self.update,
                "rt" : self.rt,
                "project" : self.project,
                "kernel" : self.kernel,
                "archs" : self.archs,
                "files" : self.files,
                "modules" : self.modules,
                "repo" : self.repo,
                "data_path" : str(self.data_path),
                "lp_path" : str(self.lp_path),
                }
