# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import configparser
import copy
import gzip
import io
import json
import logging
import platform
import os
import re
import shutil
import subprocess
from collections import OrderedDict
from pathlib import Path
from pathlib import PurePath

from natsort import natsorted

from klpbuild.utils import ARCH
from klpbuild.codestream import Codestream
from klpbuild.utils import classify_codestreams

from elftools.common.utils import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import lzma
import zstandard

class Config:
    def __init__(self, lp_name, lp_filter, data_dir=None, skips="", working_cs={}):
        # FIXME: Config is instantiated multiple times, meaning that the
        # config file gets loaded and the logs are printed as many times.

        logging.basicConfig(level=logging.INFO, format="%(message)s")

        home = Path.home()
        self.user_conf_file = Path(home, ".config/klp-build/config")
        if not self.user_conf_file.is_file():
            logging.warning(f"Warning: user configuration file not found")
            # If there's no configuration file assume fresh install.
            # Prepare the system with a default environment and conf.
            self.setup_user_env(Path(home, "klp"))

        self.load_user_conf()

        work = self.get_user_path('work_dir')

        self.lp_name = lp_name
        self.lp_path = Path(work, self.lp_name)
        self.filter = lp_filter
        self.skips = skips

        self.working_cs = OrderedDict(working_cs)
        self.codestreams = OrderedDict()
        self.codestreams_list = []
        self.conf = OrderedDict(
            {"name": str(self.lp_name), "work_dir": str(self.lp_path), "data":
             str(data_dir), }
        )

        self.conf_file = Path(self.lp_path, "conf.json")
        if self.conf_file.is_file():
            with open(self.conf_file) as f:
                self.conf = json.loads(f.read(), object_pairs_hook=OrderedDict)

        self.data = Path(self.conf.get("data", "non-existent"))
        if not self.data.exists():
            self.data = self.get_user_path('data_dir')

        self.cs_file = Path(self.lp_path, "codestreams.json")
        if self.cs_file.is_file():
            with open(self.cs_file) as f:
                self.codestreams = json.loads(f.read(), object_pairs_hook=OrderedDict)
                for _, data in self.codestreams.items():
                    self.codestreams_list.append(Codestream.from_data(self.data, data))

        # will contain the symbols from the to be livepatched object
        # cached by the codestream : object
        self.obj_symbols = {}


    def setup_user_env(self, basedir):
        workdir = Path(basedir, "livepatches")
        datadir = Path(basedir, "data")

        config = configparser.ConfigParser(allow_no_value=True)

        config['Paths'] = {'work_dir': workdir,
                           'data_dir': datadir,
                           '## SUSE internal use only ##': None,
                           '#kgr_patches_dir': 'kgraft-patches/',
                           '#kgr_patches_tests_dir': 'kgraft-patches_testscripts/',
                           '#kernel_src_dir': 'kernel-src/',
                           '#ccp_pol_dir': 'kgr-scripts/ccp-pol/'}

        logging.info(f"Creating default user configuration: '{self.user_conf_file}'")
        os.makedirs(os.path.dirname(self.user_conf_file), exist_ok=True)
        with open(self.user_conf_file, 'w') as f:
            config.write(f)

        os.makedirs(workdir, exist_ok=True)
        os.makedirs(datadir, exist_ok=True)

    def load_user_conf(self):
        config = configparser.ConfigParser()
        logging.info(f"Loading user configuration from '{self.user_conf_file}'")
        config.read(self.user_conf_file)

        # Check mandatory fields
        if 'Paths' not in config:
            raise ValueError(f"config: 'Paths' section not found")

        self.user_conf = config

    def get_user_path(self, entry, isdir=True, isopt=False):
        if entry not in self.user_conf['Paths']:
            if isopt:
                return ""
            raise ValueError(f"config: '{entry}' entry not found")

        p = Path(self.user_conf['Paths'][entry])
        if not p.exists():
            raise ValueError(f"'{p}' file or directory not found")
        if isdir and not p.is_dir():
                 raise ValueError("{p} should be a directory")
        if not isdir and not p.is_file():
                 raise ValueError("{p} should be a file")

        return p

    def lp_out_file(self, fname):
        fpath = f'{str(fname).replace("/", "_").replace("-", "_")}'
        return f"{self.lp_name}_{fpath}"

    def get_patches_dir(self):
        return Path(self.lp_path, "fixes")

    def remove_patches(self, cs, fil):
        sdir = self.get_sdir(cs)
        # Check if there were patches applied previously
        patches_dir = Path(sdir, "patches")
        if not patches_dir.exists():
            return

        fil.write(f"\nRemoving patches from {cs.name()}({cs.kernel})\n")
        fil.flush()
        err = subprocess.run(["quilt", "pop", "-a"], cwd=sdir, stderr=fil, stdout=fil)

        if err.returncode not in [0, 2]:
            raise RuntimeError(f"{cs.name()}: quilt pop failed on {sdir}: ({err.returncode}) {err.stderr}")

        shutil.rmtree(patches_dir, ignore_errors=True)
        shutil.rmtree(Path(sdir, ".pc"), ignore_errors=True)

    def apply_all_patches(self, cs, fil):
        dirs = []

        if cs.rt:
            dirs.extend([f"{cs.sle}.{cs.sp}rtu{cs.update}", f"{cle.sle}.{cs.sp}rt"])

        dirs.extend([f"{cs.sle}.{cs.sp}u{cs.update}", f"{cs.sle}.{cs.sp}"])

        if cs.sle == 15 and cs.sp < 4:
            dirs.append("cve-5.3")
        elif cs.sle == 15 and cs.sp <= 5:
            dirs.append("cve-5.14")

        patch_dirs = []

        for d in dirs:
            patch_dirs.append(Path(self.get_patches_dir(), d))

        patched = False
        sdir = self.get_sdir(cs)
        for pdir in patch_dirs:
            if not pdir.exists():
                fil.write(f"\nPatches dir {pdir} doesnt exists\n")
                continue

            fil.write(f"\nApplying patches on {cs.name()}({cs.kernel}) from {pdir}\n")
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
            raise RuntimeError(f"{cs.name()}({cs.kernel}): Failed to apply patches. Aborting")

    def get_cs_dir(self, cs, app):
        return Path(self.lp_path, app, cs.name())

    def get_work_dir(self, cs, fname, app):
        fpath = f'work_{str(fname).replace("/", "_")}'
        return Path(self.get_cs_dir(cs, app), fpath)

    def validate_config(self, cs, conf, mod):
        """
        Check if the CONFIG is enabled on the codestream. If the configuration
        entry is set as M, check if a module was specified (different from
        vmlinux).
        """
        configs = {}
        name = cs.name()

        # Validate only the specified architectures, but check if the codestream
        # is supported on that arch (like RT that is currently supported only on
        # x86_64)
        for arch in self.conf.get("archs"):
            if arch not in cs.archs:
                continue

            kconf = cs.get_boot_file("config", arch)
            with open(kconf) as f:
                match = re.search(rf"{conf}=([ym])", f.read())
                if not match:
                    raise RuntimeError(f"{name}:{arch} ({cs.kernel}): Config {conf} not enabled")

            conf_entry = match.group(1)
            if conf_entry == "m" and mod == "vmlinux":
                raise RuntimeError(f"{name}:{arch} ({cs.kernel}): Config {conf} is set as module, but no module was specified")
            elif conf_entry == "y" and mod != "vmlinux":
                raise RuntimeError(f"{name}:{arch} ({cs.kernel}): Config {conf} is set as builtin, but a module {mod} was specified")

            configs.setdefault(conf_entry, [])
            configs[conf_entry].append(f"{name}:{arch}")

        if len(configs.keys()) > 1:
            print(configs["y"])
            print(configs["m"])
            raise RuntimeError(f"Configuration mismtach between codestreams. Aborting.")

    def missing_codestream(self, cs):
        # Check if the config exists for the current ARCH since we extract code
        # for all of them when a codestream is missing.
        return not Path(self.get_odir(cs), ".config").exists()

    def get_data_dir(self, arch):
        # For the SLE usage, it should point to the place where the codestreams
        # are downloaded
        return Path(self.data, arch)

    def get_sdir(self, cs, arch=""):
        if not arch:
            arch = ARCH

        # Only -rt codestreams have a suffix for source directory
        ktype = cs.ktype.replace("-default", "")
        return Path(self.get_data_dir(arch), "usr", "src", f"linux-{cs.kernel}{ktype}")

    def get_odir(self, cs, arch=""):
        return Path(f"{self.get_sdir(cs, arch)}-obj", ARCH, cs.ktype.replace("-", ""))

    def get_ipa_file(self, cs, fname):
        return Path(self.get_odir(cs), f"{fname}.000i.ipa-clones")

    def get_mod_path(self, cs, arch, mod=""):
        if not mod or self.is_mod(mod):
            return Path(self.get_data_dir(arch), "lib", "modules", f"{cs.kname()}")
        return self.get_data_dir(arch)

    def get_tests_path(self):
        self.kgraft_tests_path = self.get_user_path('kgr_patches_tests_dir')

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


    # Update and save codestreams data
    def flush_cs_file(self, working_cs):
        for cs in working_cs:
            self.codestreams[cs.name()] = cs.data()

        with open(self.cs_file, "w") as f:
            f.write(json.dumps(self.codestreams, indent=4))


    def is_mod(self, mod):
        return mod != "vmlinux"

    # This function can be called to get the path to a module that has symbols
    # that were externalized, so we need to find the path to the module as well.
    def get_module_obj(self, arch, cs, module):
        if not self.is_mod(module):
            return cs.get_boot_file("vmlinux", arch)

        obj = cs.modules.get(module, "")
        if not obj:
            obj = self.find_module_obj(arch, cs, module)

        return Path(self.get_mod_path(cs, arch, module), obj)

    # Return only the name of the module to be livepatched
    def find_module_obj(self, arch, cs, mod, check_support=False):
        assert mod != "vmlinux"

        # Module name use underscores, but the final module object uses hyphens.
        mod = mod.replace("_", "[-_]")

        mod_path = self.get_mod_path(cs, arch, mod)
        with open(Path(mod_path, "modules.order")) as f:
            obj_match = re.search(rf"([\w\/\-]+\/{mod}.k?o)", f.read())
            if not obj_match:
                raise RuntimeError(f"{cs.name()}-{arch} ({cs.kernel}): Module not found: {mod}")

        # modules.order will show the module with suffix .o, so
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
                print(f"WARN: {cs.name()}-{arch} ({cs.kernel}): Module {mod} is not supported by SLE")

        return obj

    # Return the codestreams list but removing already patched codestreams,
    # codestreams without file-funcs and not matching the filter
    def filter_cs(self, cs_list=None, verbose=False):
        if not cs_list:
            cs_list = self.codestreams_list
        full_cs = copy.deepcopy(cs_list)

        if verbose:
            logging.info("Checking filter and skips...")

        result = []
        filtered = []
        for cs in full_cs:
            name = cs.name()

            if self.filter and not re.match(self.filter, name):
                filtered.append(name)
                continue
            elif self.skips and re.match(self.skips, name):
                filtered.append(name)
                continue

            result.append(cs)

        if verbose:
            if filtered:
                logging.info("Skipping codestreams:")
                logging.info(f'\t{" ".join(classify_codestreams(filtered))}')

        return result

    def get_elf_modinfo_entry(self, elffile, conf):
        sec = elffile.get_section_by_name(".modinfo")
        if not sec:
            return None

        # Iterate over all info on modinfo section
        for line in bytes2str(sec.data()).split("\0"):
            if line.startswith(conf):
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
        elif str(obj).endswith(".xz"):
            io_bytes = io.BytesIO(lzma.decompress(data))
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
        name = cs.name()

        self.obj_symbols.setdefault(arch, {})
        self.obj_symbols[arch].setdefault(name, {})

        if not self.obj_symbols[arch][name].get(mod, ""):
            obj = self.get_module_obj(arch, cs, mod)
            self.obj_symbols[arch][name][mod] = self.get_all_symbols_from_object(obj, True)

        ret = []

        for symbol in symbols:
            nsyms = self.obj_symbols[arch][name][mod].count(symbol)
            if nsyms == 0:
                ret.append(symbol)

            elif nsyms > 1:
                print(f"WARNING: {cs.name()}-{arch} ({cs.kernel}): symbol {symbol} duplicated on {mod}")

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
        arch_sym = {}
        # Validate only architectures supported by the codestream
        for arch in cs.archs:
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
