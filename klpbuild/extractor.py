# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import concurrent.futures
import difflib as dl
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

from natsort import natsorted

from klpbuild import utils
from klpbuild.ccp import CCP
from klpbuild.ce import CE
from klpbuild.config import Config
from klpbuild.templ import TemplateGen


class Extractor(Config):
    def __init__(self, lp_name, lp_filter, apply_patches, app, avoid_ext, workers=4):
        super().__init__(lp_name, lp_filter)

        if not self.lp_path.exists():
            raise ValueError(f"{self.lp_path} not created. Run the setup subcommand first")

        self.workers = workers

        patches = self.get_patches_dir()
        self.apply_patches = apply_patches

        if self.apply_patches and not patches.exists():
            raise ValueError("--apply-patches specified without patches. Run get-patches!")

        self.quilt_log = None
        if patches.exists():
            self.quilt_log = open(Path(patches, "quilt.log"), "w")
            self.quilt_log.truncate()

        self.total = 0
        self.make_lock = Lock()

        if self.kdir:
            if app == "ccp":
                logging.info("Forcing the use of ce since --kdir was set.")
            app = "ce"

        if app == "ccp":
            self.runner = CCP(lp_name, lp_filter, avoid_ext)
        else:
            self.runner = CE(lp_name, lp_filter, avoid_ext)

        self.app = app
        self.tem = TemplateGen(self.lp_name, self.filter, self.app)

    @staticmethod
    def unquote_output(matchobj):
        return matchobj.group(0).replace('"', "")

    @staticmethod
    def process_make_output(output):
        # some strings  have single quotes around double quotes, so remove the
        # outer quotes
        output = output.replace("'", "")

        # Remove the compiler name used to compile the object. TODO: resolve
        # when clang is used, or other cross-compilers.
        if output.startswith("gcc "):
            output = output[4:]

        # also remove double quotes from macros like -D"KBUILD....=.."
        return re.sub(r'-D"KBUILD_([\w\#\_\=\(\)])+"', Extractor.unquote_output, output)

    @staticmethod
    def get_make_cmd(out_dir, cs, filename, odir):
        filename = PurePath(filename)
        file_ = str(filename.with_suffix(".o"))

        with open(Path(out_dir, "make.out.txt"), "w") as f:
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
                f"CC={cc}",
                f"KLP_CS={cs}",
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

            completed = subprocess.check_output(make_args, cwd=odir, stderr=f).decode()
            f.write("Full output of the make command:\n")
            f.write(str(completed).strip())
            f.write("\n")
            f.flush()

            regex_str = rf"(-Wp,(\-MD|\-MMD),{ofname}\s+-nostdinc\s+-isystem.*{str(filename)});"

            f.write(f"Searching for the pattern: {regex_str}\n")
            f.flush()

            # 15.4 onwards changes the regex a little: -MD -> -MMD
            result = re.search(regex_str, str(completed).strip())
            if not result:
                raise RuntimeError(f"Failed to get the kernel cmdline for file {str(ofname)} in {cs}")

            ret = Extractor.process_make_output(result.group(1))

            # WORKAROUND: tomoyo security module uses a generated file that is
            # not part of kernel-source. For this reason, add a new option for
            # the backend process to ignore the inclusion of the missing file
            if "tomoyo" in file_:
                ret += " -DCONFIG_SECURITY_TOMOYO_INSECURE_BUILTIN_SETTING"

            # save the cmdline
            f.write(ret)

            if not " -pg " in ret:
                logging.warning(f"{cs}:{file_} is not compiled with livepatch support (-pg flag)")

            return ret

        return None

    def get_cmd_from_json(self, fname):
        with open(Path(self.get_data_dir(utils.ARCH), "compile_commands.json")) as f:
            buf = f.read()
        data = json.loads(buf)
        for d in data:
            if fname in d["file"]:
                output = d["command"]
                return Extractor.process_make_output(output)

        return None

    def process(self, args):
        i, fname, cs, fdata = args

        sdir = self.get_sdir(cs)
        odir = self.get_odir(cs)

        # The header text has two tabs
        cs_info = cs.ljust(15, " ")
        idx = f"({i}/{self.total})".rjust(15, " ")

        logging.info(f"{idx} {cs_info} {fname}")

        out_dir = self.get_work_dir(cs, fname, self.app)
        out_dir.mkdir(parents=True, exist_ok=True)

        # create symlink to the respective codestream file
        os.symlink(Path(sdir, fname), Path(out_dir, Path(fname).name))

        # Make can regenerate fixdep for each file being processed per
        # codestream, so avoid the TXTBUSY error by serializing the 'make -sn'
        # calls. Make is pretty fast, so there isn't a real slow down here.
        with self.make_lock:
            if self.kdir:
                cmd = self.get_cmd_from_json(fname)
            else:
                cmd = Extractor.get_make_cmd(out_dir, cs, fname, odir)

        args, lenv = self.runner.cmd_args(cs, fname, ",".join(fdata["symbols"]), out_dir, fdata, cmd)

        # Detect and set ibt information. It will be used in the TemplateGen
        if '-fcf-protection' in cmd:
            self.codestreams[cs]["files"][fname]["ibt"] = True
            args.extend(['-D__USE_IBT__'])

        out_log = Path(out_dir, f"{self.app}.out.txt")
        with open(out_log, "w") as f:
            # Write the command line used
            f.write(f"Executing {self.app} on {odir}\n")
            f.write("\n".join(args) + "\n")
            f.flush()
            try:
                subprocess.run(args, cwd=odir, stdout=f, stderr=f, env=lenv, check=True)
            except Exception:
                logging.warn(f"Error when processing {cs}:{fname}. Check file {out_log} for details.")
                raise

        self.codestreams[cs]["files"][fname]["ext_symbols"] = self.runner.get_symbol_list(out_dir)

        lp_out = Path(out_dir, self.lp_out_file(fname))

        # Remove the local path prefix of the klp-ccp generated comments
        # Open the file, read, seek to the beginning, write the new data, and
        # then truncate (which will use the current position in file as the
        # size)
        with open(str(lp_out), "r+") as f:
            file_buf = f.read()
            f.seek(0)
            f.write(file_buf.replace(f"from {str(sdir)}/", "from "))
            f.truncate()

        self.tem.CreateMakefile(cs, fname)

    def run(self):
        logging.info(f"Work directory: {self.lp_path}")

        working_cs = self.filter_cs(verbose=True)

        if len(working_cs) == 0:
            logging.error(f"No codestreams found")
            sys.exit(1)

        # Make it perform better by spawning a process function per
        # cs/file/funcs tuple, instead of spawning a thread per codestream
        args = []
        i = 1
        for cs, data in working_cs.items():
            # remove any previously generated files and leftover patches
            shutil.rmtree(self.get_cs_dir(cs, self.app), ignore_errors=True)
            self.remove_patches(cs, self.quilt_log)

            # Apply patches before the LPs were created
            if self.apply_patches:
                self.apply_all_patches(cs, self.quilt_log)

            for fname, fdata in data["files"].items():
                args.append((i, fname, cs, fdata))
                i += 1

        if self.kdir:
            logging.info("Refreshing compile_commands.json...")
            subprocess.check_output('./scripts/clang-tools/gen_compile_commands.py',
                                    cwd=self.data)

        logging.info(f"Extracting code using {self.app}")
        self.total = len(args)
        logging.info(f"\nGenerating livepatches for {len(args)} file(s) using {self.workers} workers...")
        logging.info("\t\tCodestream\tFile")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            results = executor.map(self.process, args)
            try:
                for result in results:
                    if result:
                        logging.error(f"{cs}: {result}")
            except:
                executor.shutdown()
                sys.exit(1)

        # Save the ext_symbols set by execute
        self.flush_cs_file()

        self.tem.refresh_codestreams(self.codestreams)

        # TODO: change the templates so we generate a similar code than we
        # already do for SUSE livepatches
        # Create the livepatches per codestream
        for cs, _ in working_cs.items():
            self.tem.GenerateLivePatches(cs)

        # For kdir setup, do not execute additional checks
        if self.kdir:
            return

        self.group_equal_files(args)

        self.tem.generate_commit_msg_file()

        logging.info("Checking the externalized symbols in other architectures...")

        missing_syms = OrderedDict()

        # Iterate over each codestream, getting each file processed, and all
        # externalized symbols of this file
        for cs, _ in working_cs.items():
            # Cleanup patches after the LPs were created if they were applied
            if self.apply_patches:
                self.remove_patches(cs, self.quilt_log)

            # Map all symbols related to each obj, to make it check the output
            # of nm only once per object
            obj_syms = {}
            for f, fdata in self.get_cs_files(cs).items():
                for obj, syms in fdata["ext_symbols"].items():
                    obj_syms.setdefault(obj, [])
                    obj_syms[obj].extend(syms)

            for obj, syms in obj_syms.items():
                missing = self.check_symbol_archs(cs, obj, syms, True)
                if missing:
                    for arch, arch_syms in missing.items():
                        missing_syms.setdefault(arch, {})
                        missing_syms[arch].setdefault(obj, {})
                        missing_syms[arch][obj].setdefault(cs, [])
                        missing_syms[arch][obj][cs].extend(arch_syms)

            self.tem.CreateKbuildFile(cs)

        if missing_syms:
            with open(Path(self.lp_path, "missing_syms"), "w") as f:
                f.write(json.dumps(missing_syms, indent=4))

            logging.warning("Symbols not found:")
            logging.warn(json.dumps(missing_syms, indent=4))

    def get_work_lp_file(self, cs, fname):
        return Path(self.get_work_dir(cs, fname, self.app), self.lp_out_file(fname))

    def get_cs_code(self, args):
        cs_files = {}

        # Mount the cs_files dict
        for arg in args:
            _, file, cs, _ = arg
            cs_files.setdefault(cs, [])

            fpath = self.get_work_lp_file(cs, file)
            with open(fpath, "r+") as fi:
                src = fi.read()

                src = re.sub(r'#include ".+kconfig\.h"', "", src)
                # Since 15.4 klp-ccp includes a compiler-version.h header
                src = re.sub(r'#include ".+compiler\-version\.h"', "", src)
                # Since RT variants, there is now an definition for auto_type
                src = src.replace(r"#define __auto_type int\n", "")
                # We have problems with externalized symbols on macros. Ignore
                # codestream names specified on paths that are placed on the
                # expanded macros
                src = re.sub(f"{self.get_data_dir(utils.ARCH)}.+{file}", "", src)
                # We can have more details that can differ for long expanded
                # macros, like the patterns bellow
                src = re.sub(rf"\.lineno = \d+,", "", src)

                # Remove any mentions to klpr_trace, since it's currently
                # buggy in klp-ccp
                src = re.sub(r".+klpr_trace.+", "", src)

                # Remove clang-extract comments
                src = re.sub(r"clang-extract: .+", "", src)

                # Reduce the noise from klp-ccp when expanding macros
                src = re.sub(r"__compiletime_assert_\d+", "__compiletime_assert", src)

                cs_files[cs].append((file, src))

        return cs_files

    # cs_list should be only two entries
    def diff_cs(self, cs_list):
        args = []
        f1 = {}
        f2 = {}
        for cs in cs_list:
            for fname, _ in self.get_cs_files(cs).items():
                args.append((_, fname, cs, _))

        cs_code = self.get_cs_code(args)
        f1 = cs_code.get(cs_list[0])
        f2 = cs_code.get(cs_list[1])

        assert len(f1) == len(f2)

        for i in range(len(f1)):
            content1 = f1[i][1].splitlines()
            content2 = f2[i][1].splitlines()

            for l in dl.unified_diff(content1, content2, fromfile=f1[i][0], tofile=f2[i][0]):
                print(l)

    # Get the code for each codestream, removing boilerplate code
    def group_equal_files(self, args):
        cs_equal = []
        processed = []

        cs_files = self.get_cs_code(args)
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
            groups.append(" ".join(utils.classify_codestreams(cs_list)))

        with open(Path(self.lp_path, self.app, "groups"), "w") as f:
            f.write("\n".join(groups))

        logging.info("\nGrouping codestreams that share the same content and files:")
        for group in groups:
            logging.info(f"\t{group}")
