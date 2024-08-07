# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import gzip
import io
import json
import logging
import os
import re
import shutil
import subprocess
from collections import OrderedDict
from pathlib import Path
from pathlib import PurePath

from natsort import natsorted

from klpbuild.utils import ARCH
from klpbuild.utils import classify_codestreams

from elftools.common.utils import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import zstandard

class Config:
    def __init__(self, lp_name, lp_filter, kdir=False, data_dir=None, skips="", working_cs={}):
        work_dir = os.getenv("KLP_WORK_DIR")
        if not work_dir:
            raise ValueError("KLP_WORK_DIR should be defined")

        work = Path(work_dir)
        if not work.is_dir():
            raise ValueError("Work dir should be a directory")

        self.lp_name = lp_name
        self.lp_path = Path(work, self.lp_name)
        self.filter = lp_filter
        self.skips = skips

        self.working_cs = OrderedDict(working_cs)
        self.codestreams = OrderedDict()
        self.cs_file = Path(self.lp_path, "codestreams.json")
        if self.cs_file.is_file():
            with open(self.cs_file) as f:
                self.codestreams = json.loads(f.read(), object_pairs_hook=OrderedDict)

        self.conf = OrderedDict(
            {"name": str(self.lp_name), "work_dir": str(self.lp_path), "data": str(data_dir), "kdir": kdir}
        )

        self.conf_file = Path(self.lp_path, "conf.json")
        if self.conf_file.is_file():
            with open(self.conf_file) as f:
                self.conf = json.loads(f.read(), object_pairs_hook=OrderedDict)

        self.kdir = self.conf.get("kdir", False)
        self.data = Path(self.conf.get("data", "non-existent"))
        if not self.data.exists():
            data_dir = os.getenv("KLP_DATA_DIR", "")
            if not data_dir:
                raise ValueError("KLP_DATA_DIR should be defined")
            self.data = Path(data_dir)

        if not self.data.is_dir():
            raise ValueError("Data dir should be a directory")

        # will contain the symbols from the to be livepatched object
        # cached by the codestream : object
        self.obj_symbols = {}

        logging.basicConfig(level=logging.INFO, format="%(message)s")

    def lp_out_file(self, fname):
        fpath = f'{str(fname).replace("/", "_").replace("-", "_")}'
        return f"{self.lp_name}_{fpath}"

    def get_patches_dir(self):
        if self.kdir:
            return Path(self.data, "fixes")
        return Path(self.lp_path, "fixes")

    def remove_patches(self, cs, fil):
        sdir = self.get_sdir(cs)
        kernel = self.get_cs_kernel(cs)
        # Check if there were patches applied previously
        patches_dir = Path(sdir, "patches")
        if not patches_dir.exists():
            return

        if not fil:
            fil = subprocess.DEVNULL

        fil.write(f"\nRemoving patches from {cs}({kernel})\n")
        fil.flush()
        err = subprocess.run(["quilt", "pop", "-a"], cwd=sdir, stderr=fil, stdout=fil)

        if err.returncode not in [0, 2]:
            raise RuntimeError(f"{cs}: quilt pop failed: {err.stderr}")

        shutil.rmtree(patches_dir, ignore_errors=True)
        shutil.rmtree(Path(sdir, ".pc"), ignore_errors=True)

    def apply_all_patches(self, cs, fil=subprocess.STDOUT):
        if self.kdir:
            patch_dirs = [self.get_patches_dir()]
        else:
            sle, sp, u, rt = self.get_cs_tuple(cs)

            dirs = []

            if rt:
                dirs.extend([f"{sle}.{sp}rtu{u}", f"{sle}.{sp}{rt}"])

            dirs.extend([f"{sle}.{sp}u{u}", f"{sle}.{sp}"])

            if sle == 15 and sp < 4:
                dirs.append("cve-5.3")
            elif sle == 15 and sp <= 5:
                dirs.append("cve-5.14")

            patch_dirs = []

            for d in dirs:
                patch_dirs.append(Path(self.get_patches_dir(), d))

        patched = False
        sdir = self.get_sdir(cs)
        kernel = self.get_cs_kernel(cs)
        for pdir in patch_dirs:
            if not pdir.exists():
                fil.write(f"\nPatches dir {pdir} doesnt exists\n")
                continue

            fil.write(f"\nApplying patches on {cs}({kernel}) from {pdir}\n")
            fil.flush()

            for patch in sorted(pdir.iterdir(), reverse=True):
                if not str(patch).endswith(".patch"):
                    continue

                err = subprocess.run(["quilt", "import", str(patch)], cwd=sdir, stderr=fil, stdout=fil)
                if err.returncode != 0:
                    fil.write("\nFailed to import patches, remove applied and try again\n")
                    self.remove_patches(cs, fil)

            err = subprocess.run(["quilt", "push", "-a"], cwd=sdir, stderr=fil, stdout=fil)

            if err.returncode != 0:
                fil.write("\nFailed to apply patches, remove applied and try again\n")
                self.remove_patches(cs, fil)

                continue

            patched = True
            fil.flush()
            # Stop the loop in the first dir that we find patches.
            break

        if not patched:
            raise RuntimeError(f"{cs}({kernel}): Failed to apply patches. Aborting")

    # All architectures supported by the codestream
    def get_cs_archs(self, cs):
        return self.get_cs_data(cs)["archs"]

    def get_cs_dir(self, cs, app):
        return Path(self.lp_path, app, cs)

    def get_work_dirname(self, fname):
        return f'work_{str(fname).replace("/", "_")}'

    def get_work_dir(self, cs, fname, app):
        fpath = f'work_{str(fname).replace("/", "_")}'
        return Path(self.get_cs_dir(cs, app), fpath)

    def get_cs_data(self, cs):
        if self.working_cs.get(cs, ""):
            return self.working_cs[cs]

        return self.codestreams[cs]

    def get_cs_modules(self, cs):
        return self.get_cs_data(cs)["modules"]

    def get_cs_kernel(self, cs):
        return self.get_cs_data(cs)["kernel"]

    def get_cs_files(self, cs):
        return self.get_cs_data(cs)["files"]

    def get_cs_tuple(self, cs):
        # There aren't codestreams with kdir
        if self.kdir:
            return (99, 99, 0, 99)

        match = re.search(r"(\d+)\.(\d+)(rt)?u(\d+)", cs)

        return (int(match.group(1)), int(match.group(2)), int(match.group(4)), match.group(3))

    def validate_config(self, cs, conf, mod):
        """
        Check if the CONFIG is enabled on the codestream. If the configuration
        entry is set as M, check if a module was specified (different from
        vmlinux).
        """
        if self.kdir:
            kconf = Path(self.data, ".config")
            with open(kconf) as f:
                match = re.search(rf"{conf}=[ym]", f.read())
                if not match:
                    raise RuntimeError(f"Config {conf} not enabled")
            return

        configs = {}
        kernel = self.get_cs_kernel(cs)

        # Validate only the specified architectures, but check if the codestream
        # is supported on that arch (like RT that is currently supported only on
        # x86_64)
        for arch in self.conf.get("archs"):
            if arch not in self.get_cs_archs(cs):
                continue

            kconf = self.get_cs_boot_file(cs, ".config", arch)
            with open(kconf) as f:
                match = re.search(rf"{conf}=([ym])", f.read())
                if not match:
                    raise RuntimeError(f"{cs}:{arch} ({kernel}): Config {conf} not enabled")

            conf_entry = match.group(1)
            if conf_entry == "m" and mod == "vmlinux":
                raise RuntimeError(f"{cs}:{arch} ({kernel}): Config {conf} is set as module, but no module was specified")
            elif conf_entry == "y" and mod != "vmlinux":
                raise RuntimeError(f"{cs}:{arch} ({kernel}): Config {conf} is set as builtin, but a module {mod} was specified")

            configs.setdefault(conf_entry, [])
            configs[conf_entry].append(f"{cs}:{arch}")

        if len(configs.keys()) > 1:
            print(configs["y"])
            print(configs["m"])
            raise RuntimeError(f"Configuration mismtach between codestreams. Aborting.")

    def missing_codestream(self, cs):
        return not self.get_cs_boot_file(cs, ".config").exists()

    def cs_is_rt(self, cs):
        return self.get_cs_data(cs).get("rt", False)

    def get_ktype(self, cs):
        return "rt" if self.cs_is_rt(cs) else "default"

    # The config file is copied from boot/config-<version> to linux-obj when we
    # extract the code, and after that we always check for the config on the
    # -obj dir. Return the original path here so we can use this function on the
    # extraction code.
    def get_cs_kernel_config(self, cs, arch):
        return Path(self.get_data_dir(arch), "boot", f"config-{self.get_cs_kernel(cs)}-{self.get_ktype(cs)}")

    def get_cs_boot_file(self, cs, file, arch=""):
        if file == "vmlinux":
            if self.kdir:
                return Path(self.get_data_dir(arch), file)
            return Path(self.get_data_dir(arch), "boot", f"{file}-{self.get_cs_kernel(cs)}-{self.get_ktype(cs)}")

        return Path(self.get_odir(cs, arch), file)

    def get_data_dir(self, arch):
        if self.kdir:
            return self.data

        return Path(self.data, arch)

    def get_sdir(self, cs, arch=""):
        if self.kdir:
            return self.data

        # Only -rt codestreams have a suffix for source directory
        ktype = f"-{self.get_ktype(cs)}"
        if ktype == "-default":
            ktype = ""

        if not arch:
            arch = ARCH

        # FIXME: For now we only download kernel-source for x86_64, but we
        # should change it to download it from the currently running
        # architecture
        arch = "x86_64"
        return Path(self.get_data_dir(arch), "usr", "src", f"linux-{self.get_cs_kernel(cs)}{ktype}")

    def get_odir(self, cs, arch=""):
        if self.kdir:
            return self.data
        return Path(f"{self.get_sdir(cs, arch)}-obj", ARCH, self.get_ktype(cs))

    def get_ipa_file(self, cs, fname):
        if self.kdir:
            return Path(self.data, f"{fname}.000i.ipa-clones")

        return Path(self.get_odir(cs), f"{fname}.000i.ipa-clones")

    def get_mod_path(self, cs, arch, mod=""):
        if self.kdir:
            return self.data

        if not mod or self.is_mod(mod):
            return Path(self.get_data_dir(arch), "lib", "modules", f"{self.get_cs_kernel(cs)}-{self.get_ktype(cs)}")
        return self.get_data_dir(arch)

    def get_tests_path(self):
        self.kgraft_tests_path = Path(Path().home(), "kgr", "kgraft-patches_testscripts")
        if not self.kgraft_tests_path.is_dir():
            raise RuntimeError(f"Couldn't find {self.kgraft_tests_path}")

        test_sh = Path(self.kgraft_tests_path, f"{self.lp_name}_test_script.sh")
        test_dir_sh = Path(self.kgraft_tests_path, f"{self.lp_name}/test_script.sh")

        if test_sh.is_file():
            test_src = test_sh
        elif test_dir_sh.is_file():
            # For more complex tests we support using a directory containing
            # as much files as needed. A `test_script.sh` is still required
            # as an entry point.
            test_src = Path(os.path.dirname(test_dir_sh))
        else:
            raise RuntimeError(f"Couldn't find {test_sh} or {test_dir_sh}")

        return test_src

    def flush_cs_file(self):
        with open(self.cs_file, "w") as f:
            f.write(json.dumps(self.codestreams, indent=4))

    def is_mod(self, mod):
        return mod != "vmlinux"

    # This function can be called to get the path to a module that has symbols
    # that were externalized, so we need to find the path to the module as well.
    def get_module_obj(self, arch, cs, module):
        obj = self.get_cs_modules(cs).get(module, "")
        if not obj:
            obj = self.find_module_obj(arch, cs, module)

        tmp_path = Path(self.get_mod_path(cs, arch, module), obj)
        if not tmp_path.exists():
            # For vmlinux files, we can have it uncompress it decompressed
            if not self.is_mod(module):
                return Path(str(tmp_path) + ".gz")

        return tmp_path

    # Return only the name of the module to be livepatched
    def find_module_obj(self, arch, cs, mod, check_support=False):
        kernel = self.get_cs_kernel(cs)
        if not self.is_mod(mod):
            if self.kdir:
                return "vmlinux"
            return f"boot/vmlinux-{kernel}-{self.get_ktype(cs)}"

        # Module name use underscores, but the final module object uses hyphens.
        mod = mod.replace("_", "[-_]")

        mod_path = self.get_mod_path(cs, arch, mod)
        with open(Path(mod_path, "modules.order")) as f:
            obj_match = re.search(rf"([\w\/\-]+\/{mod}.k?o)", f.read())
            if not obj_match:
                raise RuntimeError(f"{cs}-{arch} ({kernel}): Module not found: {mod}")

        # if kdir if set, modules.order will show the module with suffix .o, so
        # make sure the extension. Also check for multiple extensions since we
        # can have modules being compressed using different algorithms.
        for ext in [".ko", ".ko.zst", ".ko.gz"]:
            obj = str(PurePath(obj_match.group(1)).with_suffix(ext))
            if Path(mod_path, obj).exists():
                break

        if check_support:
            # Validate if the module being livepatches is supported or not
            elffile = self.get_elf_object(Path(mod_path, obj))
            if "no" == self.get_elf_modinfo_entry(elffile, "supported"):
                print(f"WARN: {cs}-{arch} ({kernel}): Module {mod} is not supported by SLE")

        return obj

    # Return the codestreams list but removing already patched codestreams,
    # codestreams without file-funcs and not matching the filter
    def filter_cs(self, cs_list=None, verbose=True):
        cs_del_list = []
        if not cs_list:
            cs_list = self.codestreams
        full_cs = copy.deepcopy(cs_list)

        if self.kdir:
            return full_cs

        if verbose:
            logging.info("Checking filter and skips...")
        filtered = []
        for cs in full_cs.keys():
            if self.filter and not re.match(self.filter, cs):
                filtered.append(cs)
            elif self.skips and re.match(self.skips, cs):
                filtered.append(cs)

        if verbose:
            if filtered:
                logging.info("Skipping codestreams:")
                logging.info(f'\t{" ".join(classify_codestreams(filtered))}')

        cs_del_list.extend(filtered)

        for cs in cs_del_list:
            full_cs.pop(cs, "")

        keys = natsorted(full_cs.keys())
        return OrderedDict((k, full_cs[k]) for k in keys)

    def get_elf_modinfo_entry(self, elffile, conf):
        sec = elffile.get_section_by_name(".modinfo")
        if not sec:
            return None

        # Iterate over all info on modinfo section
        for line in bytes2str(sec.data()).split("\0"):
            if conf in line:
                key, val = line.split("=")
                return val.strip()

        return ""

    def get_elf_object(self, obj):
        with open(obj, "rb") as f:
            data = f.read()

        # FIXME: use magic lib instead of checking the file extension
        if str(obj).endswith(".gz"):
            io_bytes = io.BytesIO(gzip.decompress(data))
        elif str(obj).endswith(".zst"):
            dctx = zstandard.ZstdDecompressor()
            io_bytes = io.BytesIO(dctx.decompress(data))
        else:
            io_bytes = io.BytesIO(data)

        return ELFFile(io_bytes)

    # Load the ELF object and return all symbols
    def get_all_symbols_from_object(self, obj, defined):
        syms = []

        elffile = self.get_elf_object(obj)
        for sec in elffile.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue

            if sec['sh_entsize'] == 0:
                continue

            for symbol in sec.iter_symbols():
                # Somehow we end up receiving an empty symbol
                if not symbol.name:
                    continue
                if str(symbol["st_shndx"]) == "SHN_UNDEF" and not defined:
                    syms.append(symbol.name)
                elif str(symbol["st_shndx"]) != "SHN_UNDEF" and defined:
                    syms.append(symbol.name)

        return syms

    # Cache the symbols using the object path. It differs for each
    # codestream and architecture
    # Return all the symbols not found per arch/obj
    def check_symbol(self, arch, cs, mod, symbols):
        self.obj_symbols.setdefault(arch, {})
        self.obj_symbols[arch].setdefault(cs, {})

        if not self.obj_symbols[arch][cs].get(mod, ""):
            obj = self.get_module_obj(arch, cs, mod)
            self.obj_symbols[arch][cs][mod] = self.get_all_symbols_from_object(obj, True)

        ret = []

        for symbol in symbols:
            nsyms = self.obj_symbols[arch][cs][mod].count(symbol)
            if nsyms == 0:
                ret.append(symbol)

            elif nsyms > 1:
                kernel = self.get_cs_kernel(cs)
                print(f"WARNING: {cs}-{arch} ({kernel}): symbol {symbol} duplicated on {mod}")

            # If len(syms) == 1 means that we found a unique symbol, which is
            # what we expect, and nothing need to be done.

        return ret

    # This functions is used to check if the symbols exist in the module they
    # we will livepatch. In this case skip_on_host argument will be false,
    # meaning that we want the symbol to checked against all supported
    # architectures before creating the livepatches.
    #
    # It is also used when we want to check if a symbol externalized in one
    # architecture exists in the other supported ones. In this case skip_on_host
    # will be True, since we trust the decisions made by the extractor tool.
    def check_symbol_archs(self, cs, mod, symbols, skip_on_host):
        data = self.get_cs_data(cs)
        arch_sym = {}
        # Validate only architectures supported by the codestream
        for arch in data["archs"]:
            if arch == ARCH and skip_on_host:
                continue

            # Skip if the arch is not supported by the livepatch code
            if not arch in self.conf.get("archs"):
                continue

            # Assign the not found symbols on arch
            syms = self.check_symbol(arch, cs, mod, symbols)
            if syms:
                arch_sym[arch] = syms

        return arch_sym
