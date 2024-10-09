# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import shutil
from pathlib import Path
import subprocess

from klpbuild.config import Config
from klpbuild.utils import ARCH


class Inliner(Config):
    def __init__(self, lp_name, lp_filter):
        super().__init__(lp_name, lp_filter)

        if not self.lp_path.exists():
            raise ValueError(f"{self.lp_path} not created. Run the setup subcommand first")

        self.ce_inline_path = shutil.which("ce-inline")
        if not self.ce_inline_path:
            raise RuntimeError("ce-inline not found. Aborting.")

    def check_inline(self, fname, func):
        ce_args = [ str(self.ce_inline_path), "-where-is-inlined" ]

        filtered = self.filter_cs()
        if not filtered:
            raise RuntimeError(f"Codestream {self.lp_filter} not found. Aborting.")

        assert len(filtered) == 1

        cs = filtered[0]

        mod = cs.files.get(fname, {}).get("module", None)
        if not mod:
            raise RuntimeError(f"File {fname} not in setup phase. Aborting.")

        ce_args.extend(["-debuginfo", str(self.get_module_obj(ARCH, cs, mod))])

        # clang-extract works without ipa-clones, so don't hard require it
        ipa_f = self.get_ipa_file(cs, fname)
        if ipa_f.exists():
            ce_args.extend(["-ipa-files", str(ipa_f)])

        ce_args.extend(["-symvers", str(self.get_boot_file(cs, "symvers"))])

        ce_args.extend([func])

        print(" ".join(ce_args))
        print(subprocess.check_output(ce_args).decode())
