# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import re

class Codestream:
    __slots__ = ("sle", "sp", "update", "rt", "project", "kernel", "archs",
                 "files", "modules", "repo")

    def __init__(self, sle, sp, update, rt, project="", kernel="",
                 archs=[], files={}, modules={}):
        self.sle = sle
        self.sp = sp
        self.update = update
        self.rt = rt
        self.project = project
        self.kernel = kernel
        self.archs = archs
        self.files = files
        self.modules = modules
        self.repo = self.get_repo()


    @classmethod
    def from_codestream(cls, cs, proj, kernel):
        # Parse SLE15-SP2_Update_25 to 15.2u25
        rt = "rt" if "-RT" in cs else ""

        sle, _, u = cs.replace("SLE", "").replace("-RT", "").split("_")
        if "-SP" in sle:
            sle, sp = sle.split("-SP")
        else:
            sle, sp = sle, "0"

        return cls(int(sle), int(sp), int(u), rt, proj, kernel)


    @classmethod
    def from_cs(cls, cs):
        match = re.search(r"(\d+)\.(\d+)(rt)?u(\d+)", cs)
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(4)), match.group(3))


    @classmethod
    def from_data(cls, data):
        return cls(data["sle"], data["sp"], data["update"], data["rt"],
                 data["project"], data["kernel"], data["archs"], data["files"],
                 data["modules"])

    def __eq__(self, cs):
        return self.sle == cs.sle and \
                self.sp == cs.sp and \
                self.update == cs.update and \
                self.rt == cs.rt


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


    def name(self):
        if self.rt:
            return f"{self.sle}.{self.sp}rtu{self.update}"

        return f"{self.sle}.{self.sp}u{self.update}"


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
                }
