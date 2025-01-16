# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import shutil
import subprocess

from klpbuild.klplib.codestreams_data import get_codestreams_dict
from klpbuild.klplib.utils import filter_codestreams, get_workdir


class Inliner():
    def __init__(self, lp_name, lp_filter):

        if not get_workdir(lp_name).exists():
            raise ValueError(f"{get_workdir(lp_name)} not created. Run the setup subcommand first")

        self.lp_filter = lp_filter
        self.ce_inline_path = shutil.which("ce-inline")
        if not self.ce_inline_path:
            raise RuntimeError("ce-inline not found. Aborting.")

    def check_inline(self, fname, func):
        ce_args = [ str(self.ce_inline_path), "-where-is-inlined" ]

        filtered = filter_codestreams(self.lp_filter, "", get_codestreams_dict())
        if not filtered:
            raise RuntimeError(f"Codestream {self.lp_filter} not found. Aborting.")

        assert len(filtered) == 1

        cs = filtered[0]

        mod = cs.files.get(fname, {}).get("module", None)
        if not mod:
            raise RuntimeError(f"File {fname} not in setup phase. Aborting.")

        ce_args.extend(["-debuginfo", str(cs.get_mod(mod))])

        # clang-extract works without ipa-clones, so don't hard require it
        ipa_f = cs.get_ipa_file(fname)
        if ipa_f.exists():
            ce_args.extend(["-ipa-files", str(ipa_f)])

        ce_args.extend(["-symvers", str(cs.get_boot_file("symvers"))])

        ce_args.extend([func])

        print(" ".join(ce_args))
        print(subprocess.check_output(ce_args).decode())
