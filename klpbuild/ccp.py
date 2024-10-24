# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import os
from pathlib import Path
import shutil

from klpbuild.config import Config
from klpbuild.utils import ARCH, is_mod


class CCP(Config):
    def __init__(self, lp_name, lp_filter, avoid_ext):
        super().__init__(lp_name, lp_filter)

        self.env = os.environ

        # List of symbols that are currently not resolvable for klp-ccp
        avoid_syms = [
            "__xadd_wrong_size",
            "__bad_copy_from",
            "__bad_copy_to",
            "rcu_irq_enter_disabled",
            "rcu_irq_enter_irqson",
            "rcu_irq_exit_irqson",
            "verbose",
            "__write_overflow",
            "__read_overflow",
            "__read_overflow2",
            "__real_strnlen",
            "__real_strlcpy",
            "twaddle",
            "set_geometry",
            "valid_floppy_drive_params",
            "__real_memchr_inv",
            "__real_kmemdup",
            "lockdep_rtnl_is_held",
            "lockdep_rht_mutex_is_held",
            "debug_lockdep_rcu_enabled",
            "lockdep_rcu_suspicious",
            "rcu_read_lock_bh_held",
            "lock_acquire",
            "preempt_count_add",
            "rcu_read_lock_any_held",
            "preempt_count_sub",
            "lock_release",
            "trace_hardirqs_off",
            "trace_hardirqs_on",
            "debug_smp_processor_id",
            "lock_is_held_type",
            "mutex_lock_nested",
            "rcu_read_lock_held",
            "__bad_unaligned_access_size",
            "__builtin_alloca",
            "tls_validate_xmit_skb_sw",
        ]
        # The backlist tells the klp-ccp to always copy the symbol code,
        # instead of externalizing. This helps in cases where different archs
        # have different inline decisions, optimizing and sometimes removing the
        # symbols.
        if avoid_ext:
            avoid_syms.extend(avoid_ext)

        self.env["KCP_EXT_BLACKLIST"] = ",".join(avoid_syms)
        self.env["KCP_READELF"] = "readelf"
        self.env["KCP_RENAME_PREFIX"] = "klp"

    # Generate the list of exported symbols
    def get_symbol_list(self, out_dir):
        exts = []

        for ext_file in ["fun_exts", "obj_exts"]:
            ext_path = Path(out_dir, ext_file)
            if not ext_path.exists():
                continue

            with open(ext_path) as f:
                for l in f:
                    l = l.strip()
                    if not l.startswith("KALLSYMS") and not l.startswith("KLP_CONVERT"):
                        continue

                    _, sym, var, mod = l.split(" ")
                    if not is_mod(mod):
                        mod = "vmlinux"

                    exts.append((sym, var, mod))

        exts.sort(key=lambda tup: tup[0])

        # store the externalized symbols and module used in this codestream file
        symbols = {}
        for ext in exts:
            sym, mod = ext[0], ext[2]
            symbols.setdefault(mod, [])
            symbols[mod].append(sym)

        return symbols

    def cmd_args(self, needs_ibt, cs, fname, funcs, out_dir, fdata, cmd):
        lp_name = self.lp_out_file(fname)
        lp_out = Path(out_dir, lp_name)

        ccp_args = [str(shutil.which("klp-ccp")) , "-P", "suse.KlpPolicy",
                    "--compiler=x86_64-gcc-9.1.0", "-i", f"{funcs}", "-o",
                    f"{str(lp_out)}", "--"]

        # -flive-patching and -fdump-ipa-clones are only present in upstream gcc
        # 15.4u0 options
        # -fno-allow-store-data-races and -Wno-zero-length-bounds
        # 15.4u1 options
        # -mindirect-branch-cs-prefix appear in 15.4u1
        # more options to be removed
        # -mharden-sls=all
        # 15.6 options
        # -fmin-function-alignment=16
        for opt in [
            "-flive-patching=inline-clone",
            "-fdump-ipa-clones",
            "-fno-allow-store-data-races",
            "-Wno-zero-length-bounds",
            "-mindirect-branch-cs-prefix",
            "-mharden-sls=all",
            "-fmin-function-alignment=16",
        ]:
            cmd = cmd.replace(opt, "")

        if cs.sle >= 15 and cs.sp >= 4:
            cmd += " -D__has_attribute(x)=0"

        ccp_args.extend(cmd.split(" "))

        ccp_args = list(filter(None, ccp_args))

        # Needed, otherwise threads would interfere with each other
        env = self.env.copy()

        env["KCP_KLP_CONVERT_EXTS"] = "1" if needs_ibt else "0"
        env["KCP_MOD_SYMVERS"] = str(cs.get_boot_file("symvers"))
        env["KCP_KBUILD_ODIR"] = str(cs.get_odir())
        env["KCP_PATCHED_OBJ"] = self.get_module_obj(ARCH, cs, fdata["module"])
        env["KCP_KBUILD_SDIR"] = str(cs.get_sdir())
        env["KCP_IPA_CLONES_DUMP"] = str(cs.get_ipa_file(fname))
        env["KCP_WORK_DIR"] = str(out_dir)

        return ccp_args, env
