# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from concurrent.futures import ThreadPoolExecutor
import itertools
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path
from pathlib import PurePath
from threading import Lock
from filelock import FileLock

from natsort import natsorted

from klpbuild.klplib import utils
from klpbuild.klplib.codestreams_data import store_codestreams, get_codestreams_data, get_codestreams_dict
from klpbuild.klplib.config import get_user_settings
from klpbuild.klplib.templ import TemplateGen


def get_cs_code(lp_name, working_cs):
    cs_files = {}

    # Mount the cs_files dict
    for cs in working_cs:
        cs_files.setdefault(cs.name(), [])

        for fpath in cs.get_lp_dir(lp_name).iterdir():
            fname = fpath.name
            with open(fpath.absolute(), "r+") as fi:
                src = fi.read()

                src = re.sub(r'#include ".+kconfig\.h"\n', "", src)
                # Since 15.4 klp-ccp includes a compiler-version.h header
                src = re.sub(r'#include ".+compiler\-version\.h"\n', "", src)
                # Since RT variants, there is now an definition for auto_type
                src = src.replace(r"#define __auto_type int\n", "")
                # We have problems with externalized symbols on macros. Ignore
                # codestream names specified on paths that are placed on the
                # expanded macros
                src = re.sub(f"{utils.get_datadir(utils.ARCH)}.+{fname}", "", src)
                # We can have more details that can differ for long expanded
                # macros, like the patterns bellow
                src = re.sub(r"\.lineno = \d+,", "", src)

                # Remove any mentions to klpr_trace, since it's currently
                # buggy in klp-ccp
                src = re.sub(r".+klpr_trace.+", "", src)

                # Reduce the noise from klp-ccp when expanding macros
                src = re.sub(r"__compiletime_assert_\d+", "__compiletime_assert", src)

                # Remove empty lines
                src = "".join([s for s in src.strip().splitlines(True) if s.strip()])

                cs_files[cs.name()].append((fname, src))

    return cs_files


def unquote_output(matchobj):
    return matchobj.group(0).replace('"', "")


def process_make_output(output):
    # some strings  have single quotes around double quotes, so remove the
    # outer quotes
    output = output.replace("'", "")

    # Remove the compiler name used to compile the object. TODO: resolve
    # when clang is used, or other cross-compilers.
    output = re.sub(r'^gcc(-\d+)?\s+', '', output)

    # also remove double quotes from macros like -D"KBUILD....=.."
    return re.sub(r'-D"KBUILD_([\w\#\_\=\(\)])+"', unquote_output, output)


def get_make_cmd(out_dir, cs, filename, odir, sdir):
    filename = PurePath(filename)
    file_ = str(filename.with_suffix(".o"))

    log_path = Path(out_dir, "make.out.txt")
    with open(log_path, "w") as f:
        # Corner case for lib directory, that fails with the conventional
        # way of grabbing the gcc args used to compile the file. If then
        # need to ask the make to show the commands for all files inside the
        # directory. Later process_make_output will take care of picking
        # what is interesting for klp-build
        if filename.parent == PurePath("arch/x86/lib") or filename.parent == PurePath("drivers/block/aoe"):
            file_ = str(filename.parent) + "/"

        gcc_ver = int(subprocess.check_output(["gcc", "-dumpversion"]).decode().strip())
        # gcc12 and higher have a problem with kernel and xrealloc implementation
        if gcc_ver < 12:
            cc = "gcc"
        # if gcc12 or higher is the default compiler, check if gcc7 is available
        elif shutil.which("gcc-7"):
            cc = "gcc-7"
        else:
            raise RuntimeError("Only gcc12 or higher are available, and it's problematic with kernel sources")

        make_args = [
            "make",
            "-sn",
            "--ignore-errors",
            f"CC={cc}",
            f"KLP_CS={cs.name()}",
            f"HOSTCC={cc}",
            "WERROR=0",
            "CFLAGS_REMOVE_objtool=-Werror",
            file_,
        ]

        f.write(f"Executing make on {odir}\n")
        f.write(" ".join(make_args))
        f.write("\n")
        f.flush()

        ofname = "." + filename.name.replace(".c", ".o.d")
        ofname = Path(filename.parent, ofname)

        try:
            completed = subprocess.check_output(make_args, cwd=odir,
                                                stderr=f).decode().strip()
            f.write("Full output of the make command:\n")
            f.write(str(completed))
            f.write("\n")
            f.flush()
        except Exception as exc:
            raise RuntimeError(f"Failed to run make for {cs.name()} ({cs.kernel}). Check file {str(log_path)} for more details.") from exc

        # 15.4 onwards changes the regex a little: -MD -> -MMD
        # 15.6 onwards we don't have -isystem.
        #      Also, it's more difficult to eliminate the objtool command
        #      line, so try to search until the fixdep script
        for regex in [
                rf"(-Wp,(\-MD|\-MMD),{ofname}\s+-nostdinc\s+-isystem.*{str(filename)});",
                rf"(-Wp,(\-MD|\-MMD),{ofname}\s+-nostdinc\s+.*-c -o {file_} {sdir}/{filename})\s+;.*fixdep"
                ]:
            f.write(f"Searching for the pattern: {regex}\n")
            f.flush()

            result = re.search(regex, str(completed).strip())
            if result:
                break

            f.write("Not found\n")
            f.flush()

        if not result:
            raise RuntimeError(f"Failed to get the kernel cmdline for file {str(ofname)} in {cs.name()}. Check file {str(log_path)} for more details.")

        ret = process_make_output(result.group(1))

        # WORKAROUND: tomoyo security module uses a generated file that is
        # not part of kernel-source. For this reason, add a new option for
        # the backend process to ignore the inclusion of the missing file
        if "tomoyo" in file_:
            ret += " -DCONFIG_SECURITY_TOMOYO_INSECURE_BUILTIN_SETTING"

        # save the cmdline
        f.write(ret)

        if " -pg " not in ret:
            logging.warning("%s:%s is not compiled with livepatch support (-pg flag)", cs.name(), file_)

        return ret


def get_symbol_list(out_dir):
    # Generate the list of exported symbols
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
                # Module names should not use dashes
                mod = mod.replace("-", "_")
                if not utils.is_mod(mod):
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


def get_cmd_from_json(cs, fname):
    cc_file = cs.get_obj_dir()/"compile_commands.json"

    # Older codestreams doens't support compile_commands.json, so use make for them
    if not cc_file.exists():
        return None

    with open(cc_file) as f:
        buf = f.read()
    data = json.loads(buf)
    for d in data:
        if fname in d["file"]:
            output = d["command"]
            # The arguments found on the file point to '..', since they are generated
            # when the kernel is compiled. Replace the first '..' on each file
            # path by the codestream kernel source directory since klp-ccp needs to
            # reach the files.
            cmd = process_make_output(output)
            return cmd.replace(" ..", f" {str(cs.get_src_dir())}").replace("-I..", f"-I{str(cs.get_src_dir())}")

    raise RuntimeError(f"Couldn't find cmdline for {fname} on {str(cc_file)}. Aborting")


def print_env_vars(fhandle, env):
    fhandle.write("Env vars:\n")

    for k, v in env.items():
        if not k.startswith("KCP"):
            continue

        fhandle.write(f"{k}={v}\n")


def get_patches_dir(lp_name):
    return utils.get_workdir(lp_name)/"fixes"


# Get the code for each codestream, removing boilerplate code
def group_equal_files(lp_name, working_cs):
    cs_equal = []
    processed = []

    cs_files = get_cs_code(lp_name, working_cs)
    toprocess = list(cs_files.keys())
    while len(toprocess):
        current_cs_list = []

        # Get an element, and check if it wasn't associated with a previous
        # codestream
        cs = toprocess.pop(0)
        if cs in processed:
            continue

        # last element, it's different from all other codestreams, so add it
        # to the cs_equal alone.
        if not toprocess:
            cs_equal.append([cs])
            break

        # start a new list with the current element to compare with others
        current_cs_list.append(cs)
        data_cs = cs_files[cs]
        len_data = len(data_cs)

        # Compare the file names, and file content between codestrams,
        # trying to find ones that have the same files and contents
        for cs_proc in toprocess:
            data_proc = cs_files[cs_proc]

            if len_data != len(data_proc):
                continue

            ok = True
            for i in range(len_data):
                file, src = data_cs[i]
                file_proc, src_proc = data_proc[i]

                if file != file_proc or src != src_proc:
                    ok = False
                    break

            # cs is equal to cs_proc, with the same number of files, same
            # file names, and the files have the same content. So we don't
            # need to process cs_proc later in the process
            if ok:
                processed.append(cs_proc)
                current_cs_list.append(cs_proc)

        # Append the current list of equal codestreams to a global list to
        # be grouped later
        cs_equal.append(natsorted(current_cs_list))

    # cs_equal will contain a list of lists with codestreams that share the
    # same code
    groups = []
    for cs_list in cs_equal:
        groups.append(utils.classify_codestreams_str(cs_list))

    # Sort between all groups of codestreams
    groups = natsorted(groups)

    with open(utils.get_workdir(lp_name)/"ccp"/"groups", "w") as f:
        f.write("\n".join(groups))

    logging.info("\nGrouping codestreams that share the same content and files:")
    for group in groups:
        logging.info("\t%s", group)


def remove_patches(cs, fil):
    sdir = cs.get_src_dir()
    # Check if there were patches applied previously
    patches_dir = Path(sdir, "patches")
    if not patches_dir.exists():
        return

    fil.write(f"\nRemoving patches from {cs.name()}({cs.kernel})\n")
    fil.flush()
    err = subprocess.run(["quilt", "pop", "-a"], cwd=sdir, stderr=fil, stdout=fil, check=False)

    if err.returncode not in [0, 2]:
        raise RuntimeError(f"{cs.name()}: quilt pop failed on {sdir}: ({err.returncode}) {err.stderr}")

    shutil.rmtree(patches_dir, ignore_errors=True)
    shutil.rmtree(Path(sdir, ".pc"), ignore_errors=True)


def apply_all_patches(lp_name, cs, fil):
    dirs = []

    if cs.rt:
        dirs.extend([f"{cs.sle}.{cs.sp}rtu{cs.update}", f"{cs.sle}.{cs.sp}rt"])

    dirs.extend([f"{cs.sle}.{cs.sp}u{cs.update}", f"{cs.sle}.{cs.sp}"])

    if cs.sle == 15 and cs.sp < 4:
        dirs.append("cve-5.3")
    elif cs.sle == 15 and cs.sp <= 5:
        dirs.append("cve-5.14")

    patch_dirs = []

    for d in dirs:
        patch_dirs.append(Path(get_patches_dir(lp_name), d))

    patched = False
    sdir = cs.get_src_dir()
    for pdir in patch_dirs:
        if not pdir.exists():
            fil.write(f"\nPatches dir {pdir} doesnt exists\n")
            continue

        fil.write(f"\nApplying patches on {cs.name()}({cs.kernel}) from {pdir}\n")
        fil.flush()

        for patch in sorted(pdir.iterdir(), reverse=True):
            if not str(patch).endswith(".patch"):
                continue

            err = subprocess.run(["quilt", "import", str(patch)], cwd=sdir, stderr=fil, stdout=fil, check=False)
            if err.returncode != 0:
                fil.write("\nFailed to import patches, remove applied and try again\n")
                remove_patches(cs, fil)

        err = subprocess.run(["quilt", "push", "-a"], cwd=sdir, stderr=fil, stdout=fil, check=False)
        if err.returncode != 0:
            fil.write("\nFailed to apply patches, remove applied and try again\n")
            remove_patches(cs, fil)

            continue

        patched = True
        fil.flush()
        # Stop the loop in the first dir that we find patches.
        break

    if not patched:
        raise RuntimeError(f"{cs.name()}({cs.kernel}): Failed to apply patches. Aborting")


def cmd_args(lp_name, cs, fname, out_dir, fdata, cmd, avoid_ext):
    lp_out = Path(out_dir, cs.lp_out_file(lp_name, fname))

    funcs = ",".join(fdata["symbols"])

    ccp_args = [str(shutil.which("klp-ccp")), "-P", "suse.KlpPolicy",
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
        "-Wno-dangling-pointer",
    ]:
        cmd = cmd.replace(opt, "")

    if cs.is_micro or (cs.sle >= 15 and cs.sp >= 4):
        cmd += " -D__has_attribute(x)=0"

    ccp_args.extend(cmd.split(" "))

    ccp_args = list(filter(None, ccp_args))

    # Needed, otherwise threads would interfere with each other
    env = os.environ.copy()

    env["KCP_KLP_CONVERT_EXTS"] = "1" if cs.needs_ibt else "0"
    env["KCP_MOD_SYMVERS"] = str(cs.get_boot_file("symvers"))
    env["KCP_KBUILD_ODIR"] = str(cs.get_obj_dir())
    env["KCP_PATCHED_OBJ"] = str(utils.get_datadir(utils.ARCH)/cs.get_mod(fdata["module"]))
    env["KCP_KBUILD_SDIR"] = str(cs.get_src_dir())
    env["KCP_IPA_CLONES_DUMP"] = str(cs.get_ipa_file(fname))
    env["KCP_WORK_DIR"] = str(out_dir)
    env["KCP_READELF"] = "readelf"
    env["KCP_RENAME_PREFIX"] = "klp"

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

    env["KCP_EXT_BLACKLIST"] = ",".join(avoid_syms)

    return ccp_args, env


class Extractor():
    def __init__(self, lp_name, apply_patches):

        self.lp_name = lp_name
        self.sdir_lock = FileLock(utils.get_datadir()/utils.ARCH/"sdir.lock")
        self.sdir_lock.acquire()

        if not utils.get_workdir(lp_name).exists():
            raise ValueError(f"{utils.get_workdir(lp_name)} not created. Run the setup subcommand first")

        patches = get_patches_dir(lp_name)
        self.apply_patches = apply_patches

        if self.apply_patches and not patches.exists():
            raise ValueError("patches do not exist!")

        if patches.exists():
            self.quilt_log = open(Path(patches, "quilt.log"), "w")
            self.quilt_log.truncate()
        else:
            self.quilt_log = open("/dev/null", "w")

        self.total = 0
        self.make_lock = Lock()

    def __del__(self):
        if self.sdir_lock:
            self.sdir_lock.release()
            os.remove(self.sdir_lock.lock_file)

    def process(self, args, avoid_ext):
        i, fname, cs, fdata = args

        sdir = cs.get_src_dir()
        odir = cs.get_obj_dir()

        # The header text has two tabs
        cs_info = cs.name().ljust(15, " ")
        idx = f"({i}/{self.total})".rjust(15, " ")

        logging.info(f"{idx} {cs_info} {fname}")

        out_dir = cs.get_ccp_work_dir(self.lp_name, fname)
        out_dir.mkdir(parents=True, exist_ok=True)

        # create symlink to the respective codestream file
        os.symlink(Path(sdir, fname), Path(out_dir, Path(fname).name))

        # Make can regenerate fixdep for each file being processed per
        # codestream, so avoid the TXTBUSY error by serializing the 'make -sn'
        # calls. Make is pretty fast, so there isn't a real slow down here.
        cmd = get_cmd_from_json(cs, fname)
        if not cmd:
            with self.make_lock:
                cmd = get_make_cmd(out_dir, cs, fname, odir, sdir)

        args, lenv = cmd_args(self.lp_name, cs, fname, out_dir, fdata, cmd, avoid_ext)

        # Detect and set ibt information. It will be used in the TemplateGen
        if '-fcf-protection' in cmd or cs.needs_ibt:
            cs.files[fname]["ibt"] = True

        out_log = Path(out_dir, "ccp.out.txt")
        with open(out_log, "w+") as f:
            # Write the command line used
            f.write(f"Executing ccp on {odir}\n")
            print_env_vars(f, lenv)
            f.write("\n".join(args) + "\n")
            f.flush()

            start_pos = f.tell()
            try:
                subprocess.run(args, cwd=odir, stdout=f, stderr=f, env=lenv, check=True)
            except Exception as exc:
                raise RuntimeError(f"Error when processing {cs.name()}:{fname}. Check file {out_log} for details.") from exc

            # Look for optimized function warnings in the output of the command
            f.seek(start_pos)
            symbol_pattern = r'warning: optimized function "([^"]+)" in callgraph'
            for line in f:
                match = re.search(symbol_pattern, line)
                if match:
                    opt_symbol_name = match.group(1)
                    symbol_name = opt_symbol_name.split(".")[0]
                    logging.warning("Warning when processing %s:%s: "
                                    "Symbol %s contains optimized clone: %s",
                                    cs.name(), fname, symbol_name, opt_symbol_name)
                    logging.warning(f"Make sure to patch all the callers of %s.", symbol_name)

        cs.files[fname]["ext_symbols"] = get_symbol_list(out_dir)

        lp_out = Path(out_dir, cs.lp_out_file(self.lp_name, fname))

        # Remove the local path prefix of the klp-ccp generated comments
        # Open the file, read, seek to the beginning, write the new data, and
        # then truncate (which will use the current position in file as the
        # size)
        with open(str(lp_out), "r+") as f:
            file_buf = f.read()
            f.seek(0)
            f.write(file_buf.replace(f"from {str(sdir)}/", "from "))
            f.truncate()

    def run(self, lp_filter, avoid_ext):
        logging.info(f"Work directory: %s", utils.get_workdir(self.lp_name))

        working_cs = utils.filter_codestreams(lp_filter, get_codestreams_dict(), verbose=True)

        if len(working_cs) == 0:
            logging.error("No codestreams found")
            sys.exit(1)

        # Make it perform better by spawning a process function per
        # cs/file/funcs tuple, instead of spawning a thread per codestream
        args = []
        i = 1
        for cs in working_cs:
            # remove any previously generated files and leftover patches
            shutil.rmtree(cs.get_ccp_dir(self.lp_name), ignore_errors=True)
            remove_patches(cs, self.quilt_log)

            # Apply patches before the LPs were created
            if self.apply_patches:
                apply_all_patches(self.lp_name, cs, self.quilt_log)

            for fname, fdata in cs.files.items():
                args.append((i, fname, cs, fdata))
                i += 1

        workers = int(get_user_settings("workers"))
        logging.info("Extracting code using ccp")
        self.total = len(args)
        logging.info("\nGenerating livepatches for %d file(s) using %d workers...", len(args), workers)
        logging.info("\t\tCodestream\tFile")

        with ThreadPoolExecutor(max_workers=workers) as executor:
            try:
                futures = executor.map(self.process, args, itertools.repeat(avoid_ext))
                for future in futures:
                    if future:
                        logging.error(future)
            except Exception as exc:
                raise RuntimeError(str(exc)) from exc

        # Save the ext_symbols set by execute
        store_codestreams(self.lp_name, working_cs)

        tem = TemplateGen(self.lp_name)

        # TODO: change the templates so we generate a similar code than we
        # already do for SUSE livepatches
        # Create the livepatches per codestream
        for cs in working_cs:
            tem.generate_livepatches(cs)

        group_equal_files(self.lp_name, working_cs)

        logging.info("Checking the externalized symbols in other architectures...")

        missing_syms = OrderedDict()

        # Iterate over each codestream, getting each file processed, and all
        # externalized symbols of this file
        for cs in working_cs:
            # Cleanup patches after the LPs were created if they were applied
            if self.apply_patches:
                remove_patches(cs, self.quilt_log)

            # Map all symbols related to each obj, to make it check the symbols
            # only once per object
            obj_syms = {}
            for f, fdata in cs.files.items():
                for obj, syms in fdata["ext_symbols"].items():
                    obj_syms.setdefault(obj, [])
                    obj_syms[obj].extend(syms)

            for obj, syms in obj_syms.items():
                missing = cs.check_symbol_archs(get_codestreams_data('archs'), obj, syms, True)
                if missing:
                    for arch, arch_syms in missing.items():
                        missing_syms.setdefault(arch, {})
                        missing_syms[arch].setdefault(obj, {})
                        missing_syms[arch][obj].setdefault(cs.name(), [])
                        missing_syms[arch][obj][cs.name()].extend(arch_syms)

        if missing_syms:
            with open(utils.get_workdir(self.lp_name)/"missing_syms", "w") as f:
                f.write(json.dumps(missing_syms, indent=4))

            logging.warning("Symbols not found:")
            logging.warning(json.dumps(missing_syms, indent=4))
