import os
from pathlib import Path

from klpbuild.config import Config
from klpbuild.utils import ARCH


class CCP(Config):
    def __init__(self, bsc, bsc_filter, avoid_ext):
        super().__init__(bsc, bsc_filter)

        self.env = os.environ

        # Prefer the env var to the HOME directory location
        ccp_path = os.getenv("KLP_CCP_PATH", "")
        if ccp_path and not Path(ccp_path).is_file():
            raise RuntimeError("KLP_CCP_PATH does not point to a file")

        elif not ccp_path:
            ccp_path = Path(Path().home(), "kgr", "ccp", "build", "klp-ccp")
            if not ccp_path.exists():
                raise RuntimeError(
                    "klp-ccp not found in ~/kgr/ccp/build/klp-ccp. Please set KLP_CCP_PATH env var to a valid klp-ccp binary"
                )

        self.ccp_path = str(ccp_path)

        pol_path = os.getenv("KLP_CCP_POL_PATH")
        if pol_path and not Path(pol_path).is_dir():
            raise RuntimeError("KLP_CCP_POL_PATH does not point to a directory")

        elif not pol_path:
            pol_path = Path(Path().home(), "kgr", "scripts", "ccp-pol")
            if not pol_path.is_dir():
                raise RuntimeError(
                    "ccp-pol not found at ~/kgr/scripts/ccp-pol/.  Please set KLP_CCP_POL_PATH env var to a valid ccp-pol directory"
                )

        self.pol_path = str(pol_path)

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
                    if not l.startswith("KALLSYMS"):
                        continue

                    _, sym, var, mod = l.split(" ")
                    if not self.is_mod(mod):
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

    def cmd_args(self, cs, fname, funcs, out_dir, fdata, cmd):
        sdir = self.get_sdir(cs)
        odir = self.get_odir(cs)

        lp_name = self.lp_out_file(fname)
        lp_out = Path(out_dir, lp_name)
        ppath = self.pol_path

        ccp_args = [self.ccp_path]
        for arg in [
            "may-include-header",
            "can-externalize-fun",
            "shall-externalize-fun",
            "shall-externalize-obj",
            "modify-externalized-sym",
            "rename-rewritten-fun",
        ]:
            ccp_args.append(f"--pol-cmd-{arg}={ppath}/kgr-ccp-pol-{arg}.sh")

        ccp_args.append(f"--pol-cmd-modify-patched-fun-sym={ppath}/kgr-ccp-pol-modify-patched-sym.sh")

        ccp_args.extend(["--compiler=x86_64-gcc-9.1.0", "-i", f"{funcs}", "-o", f"{str(lp_out)}", "--"])

        # -flive-patching and -fdump-ipa-clones are only present in upstream gcc
        # 15.4u0 options
        # -fno-allow-store-data-races and -Wno-zero-length-bounds
        # 15.4u1 options
        # -mindirect-branch-cs-prefix appear in 15.4u1
        # more options to be removed
        # -mharden-sls=all
        for opt in [
            "-flive-patching=inline-clone",
            "-fdump-ipa-clones",
            "-fno-allow-store-data-races",
            "-Wno-zero-length-bounds",
            "-mindirect-branch-cs-prefix",
            "-mharden-sls=all",
        ]:
            cmd = cmd.replace(opt, "")

        sle, sp, _, _ = self.get_cs_tuple(cs)
        if sle >= 15:
            if sp >= 2:
                cmd += " -D_Static_assert(e,m)="
            if sp >= 4:
                cmd += " -D__auto_type=int"
                cmd += " -D__has_attribute(x)=0"

        ccp_args.extend(cmd.split(" "))

        ccp_args = list(filter(None, ccp_args))

        # Needed, otherwise threads would interfere with each other
        env = self.env.copy()

        env["KCP_MOD_SYMVERS"] = str(self.get_cs_boot_file(cs, "symvers"))
        env["KCP_KBUILD_ODIR"] = str(odir)
        env["KCP_PATCHED_OBJ"] = self.get_module_obj(ARCH, cs, fdata["module"])
        env["KCP_KBUILD_SDIR"] = str(sdir)
        env["KCP_IPA_CLONES_DUMP"] = str(self.get_ipa_file(cs, fname))
        env["KCP_WORK_DIR"] = str(out_dir)

        return ccp_args, env
