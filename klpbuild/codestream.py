# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

class Codestream:
    __slots__ = ("sle", "sp", "update", "rt", "project", "kernel", "branch",
                 "archs", "files", "modules", "repo")

    def __init__(self, sle, sp, update, rt, project="", kernel="",
                 branch="", archs=[], files={}, modules={}):
        self.sle = sle
        self.sp = sp
        self.update = update
        self.rt = rt
        self.project = project
        self.kernel = kernel
        self.branch = branch
        self.archs = archs
        self.files = files
        self.modules = modules
        self.repo = self.get_repo()


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


    def data(self):
        return {
                "sle" : self.sle,
                "sp" : self.sp,
                "update" : self.update,
                "rt" : self.rt,
                "project" : self.project,
                "kernel" : self.kernel,
                "archs" : self.archs,
                "modules" : self.modules,
                }
