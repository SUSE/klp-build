# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from pathlib import Path, PurePath
import re
import subprocess

from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.ksrc import ksrc_read_rpm_file, ksrc_is_module_supported
from klpbuild.klplib.utils import ARCH, get_workdir, is_mod, get_all_symbols_from_object, get_datadir
from klpbuild.klplib.kernel_tree import init_cs_kernel_tree, file_exists_in_tag, read_file_in_tag

class Codestream:
    __slots__ = ("__name", "sle", "sp", "update", "rt", "is_micro", "is_slfo",
                 "__project", "patchid", "kernel", "archs", "files", "modules",
                 "repo", "configs")

    def __init__(self, name, project="", patchid="", kernel="",
                 archs=None, files=None, modules=None, configs=None):

        self.__name = name

        match = re.search(r"(\d+)\.(\d+)(rt)?u(\d+)", name)
        if not match:
            raise ValueError("Name format error")
        assert match.group(3) in (None, "rt")

        self.sle = int(match.group(1))
        self.sp = int(match.group(2))
        self.rt = match.group(3) or ""
        self.update = int(match.group(4))

        self.is_micro = self.sle == 6
        # SLFO codestreams use the PATCHID informatino to find the packages
        self.is_slfo = self.is_micro or self.sle > 15
        self.__project = project
        self.patchid = patchid
        self.kernel = kernel

        self.archs = archs if archs is not None else self.__get_default_archs()
        self.files = files if files is not None else {}
        self.modules = modules if modules is not None else {}
        self.configs = configs if configs is not None else {}


    @classmethod
    def from_data(cls, data):
        return cls(data["name"],data["project"], data["patchid"],
                   data["kernel"], data["archs"], data["files"],
                   data["modules"], data["configs"])

    def to_data(self):
        return {
                "name": self.__name,
                "project": self.__project,
                "patchid": self.patchid,
                "kernel" : self.kernel,
                "archs" : self.archs,
                "files" : self.files,
                "modules" : self.modules,
                "configs" : self.configs,
                }

    def __eq__(self, cs):
        return self.sle == cs.sle and \
                self.sp == cs.sp and \
                self.update == cs.update and \
                self.rt == cs.rt


    def get_src_dir(self, arch=ARCH, init=True):
        # Before sle16, only -rt codestreams have a suffix for source directory
        has_rt_suffix = self.rt and self.sle < 16
        name = self.get_full_kernel_name() if has_rt_suffix else self.kernel
        src_dir = get_datadir(arch)/"usr"/"src"/f"linux-{name}"
        if init:
            init_cs_kernel_tree(self.kernel, src_dir)
        return src_dir


    def get_obj_dir(self):
        return Path(f"{self.get_src_dir(ARCH, init=False)}-obj", ARCH, self.get_kernel_type())


    def get_ipa_file(self, fname):
        return Path(self.get_obj_dir(), f"{fname}.000i.ipa-clones")

    def get_config_content(self, arch=ARCH):
        """
        Returns the content of the config from the kernel-source git directory.
        This content sligthly differs from the config file shipped with the
        rpms, but this difference should not affect the entries that
        enable/disable portion of the source.
        """

        target_config_file = f"config/{arch}/{self.get_kernel_type()}"
        if self.sle < 16 or not self.rt:
            return ksrc_read_rpm_file(self.kernel, target_config_file)

        # From SLE16, the same source is used both for -default kernel and for
        # -rt kernel. The config file needs to be retrieved by mergind the
        # default config with the rt config on the fly as we no longer have a
        # dedicated -rt one
        ksrc_path = get_user_path("kernel_src_dir")
        default_config_file = f"{ksrc_path}/config/{arch}/default"
        file = f"{ksrc_path}/{target_config_file}"
        script = f"{ksrc_path}/scripts/config-merge"
        cmd = [script, default_config_file, file]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout



    def get_boot_file(self, file, arch=ARCH):
        assert file.startswith("vmlinux") or file.startswith("config") or file.startswith("symvers")
        if self.is_slfo:
            return Path(self.get_mod_path(arch), file)

        # Strip the suffix from the filename so we can add the kernel version in the middle
        fname = f"{Path(file).stem}-{self.get_full_kernel_name()}{Path(file).suffix}"
        return get_datadir(arch)/"boot"/fname

    def get_repo(self):
        if self.update == 0 or self.is_slfo:
            return "standard"

        repo = f"SUSE_SLE-{self.sle}"
        if self.sp != 0:
            repo = f"{repo}-SP{self.sp}"

        repo = f"{repo}_Update"

        # On 15.5 the RT kernels and in the main codestreams
        if not self.rt or (self.sle == 15 and self.sp == 5):
            return repo

        return f"{repo}_Products_SLERT_Update"

    def get_project_name(self):
        """
        Return the project set on the constructor. Assert that a project was
        set when the Codestream object was created.
        """
        assert self.__project

        return self.__project

    def __get_default_archs(self):
        # RT is supported only on x86_64 at the moment
        if self.rt:
            return ["x86_64"]
        # MICRO 6.0 doesn't support ppc64le
        elif self.is_micro:
            return ["x86_64", "s390x"]
        # We support all architecture for all other codestreams
        return ["x86_64", "s390x", "ppc64le"]


    def set_files(self, files):
        self.files = files


    def get_kernel_type(self, suffix=False):
        dash = "-" if suffix else ""
        suffix = "rt" if self.rt else "default"
        return dash + suffix


    def get_full_kernel_name(self):
        """Returns the kernel name with flavor suffix"""
        # some kernel versions already have the suffix, some other don't
        ktype = "" if "-rt" in self.kernel else self.get_kernel_type(suffix=True)
        return self.kernel + ktype


    def base_cs_name(self):
        """
        Return the base codestream name, optionally including 'rt' if it's a
        real-time kernel.
        """
        return f"{self.sle}.{self.sp}{self.rt}"


    def full_cs_name(self):
        """Return the full codestream name including the update number."""
        return f"{self.base_cs_name()}u{self.update}"


    def get_ccp_dir(self, lp_name):
        """
        Get the path to the ccp directory of the current codestream.

        Args:
            lp_name (str): The name of the live patch.

        Returns:
            Path: The path to the ccp directory of the current codestream.
        """
        return get_workdir(lp_name)/"ccp"/self.full_cs_name()


    def get_lp_dir(self, lp_name):
        """
        Get the path to the extracted livepatches directory of the current codestream.

        Args:
            lp_name (str): The name of the live patch.

        returns:
            path: The path to the extracted livepatches directory of the current codestream.
        """
        return self.get_ccp_dir(lp_name)/"lp"


    def get_ccp_work_dir(self, lp_name, fname):
        """
        Get the path to the klp-ccp working directory of the current codestream.

        Args:
            lp_name (str): The name of the live patch.
            fname (str): The name of the file we're extracting.

        returns:
            Path: The path to the klp-ccp working directory of the current codestream.
        """
        fpath = f'work_{str(fname).replace("/", "_")}'
        return self.get_ccp_dir(lp_name)/fpath


    def get_base_product_name(self):
        """
        Return the base product name based on internal attributes.

        Example:
            15.6rtu2:       'SLE15-SP6-RT'
            6u0:            'MICRO-6-0'
        """
        rt = "-RT" if self.rt else ""

        if self.is_micro:
            return f"MICRO-{self.sle}-{self.sp}{rt}"

        sp = f"-SP{self.sp}" if self.sp else ""
        return f"SLE{self.sle}{sp}{rt}"


    def get_full_product_name(self):
        """
        Return the full product name including the update number.

        Example:
            15.6rtu2:       'SLE15-SP6-RT_Update_0'
            6u0:            'MICRO-6-0_Update_0'
        """
        product_base_name = self.get_base_product_name()
        return f"{product_base_name}_Update_{self.update}"

    def get_package_name(self):
        """
        Return the kernel package name related to the codestream
        """
        pkg = "kernel-default"

        if self.is_slfo:
            pkg = self.patchid

        elif self.rt:
            pkg = "kernel-rt"

        if self.get_repo() != "standard":
            pkg = f"{pkg}.{self.get_repo()}"

        return pkg

    def needs_ibt(self):
        return self.is_slfo or (self.sle == 15 and self.sp >= 6)

    # 15.4 onwards we don't have module_mutex, so template generates
    # different code
    def is_mod_mutex(self):
        return not self.is_slfo and (self.sle < 15 or (self.sle == 15 and self.sp < 4))

    def get_mod_path(self, arch):
        # Micro already has support for usrmerge
        if self.is_slfo:
            mod_path = Path("usr", "lib")
        else:
            mod_path = Path("lib")

        return get_datadir(arch)/mod_path/"modules"/self.get_full_kernel_name()

    # A codestream can be patching multiple objects, so get the path related to
    # the module that we are interested
    def get_mod(self, mod):
        return self.modules[mod]

    def is_module_supported(self, mod):
        return ksrc_is_module_supported(mod, self.kernel)

    # Returns the path to the kernel-obj's build dir, used when build testing
    # the generated module
    def get_kernel_build_path(self, arch):
        return Path(self.get_mod_path(arch), "build")


    def get_all_configs(self, conf):
        """
        Get the config value for all supported architectures of a codestream. If
        the configuration is not set the return value will be an empty dict.
        """
        configs = {}

        for arch in self.archs:
            kconf = self.get_config_content(arch)

            match = re.search(rf"{conf}=([ym])", kconf)
            if match:
                configs[arch] = match.group(1)

        return configs

    def validate_config(self, archs, conf, mod):
        configs = {}
        cs_config = self.get_all_configs(conf)

        # Validate only the specified architectures, but check if the codestream
        # is supported on that arch (like RT that is currently supported only on
        # x86_64)
        for arch in archs:
            # Check if the desired CONFIG entry is set on the codestreams's supported
            # architectures, by iterating on the specified architectures from the setup command.
            if arch not in self.archs:
                continue

            try:
                conf_entry = cs_config.pop(arch)
            except KeyError as exc:
                raise RuntimeError(f"{self.full_cs_name()}: {conf} not set on {arch}. Aborting") from exc

            if conf_entry == "m" and mod == "vmlinux":
                raise RuntimeError(f"{self.full_cs_name()}:{arch} ({self.kernel}): Config {conf} is set as module, but no module was specified")
            if conf_entry == "y" and mod != "vmlinux":
                raise RuntimeError(f"{self.full_cs_name()}:{arch} ({self.kernel}): Config {conf} is set as builtin, but a module {mod} was specified")

            configs.setdefault(conf_entry, [])
            configs[conf_entry].append(f"{self.full_cs_name()}:{arch}")

        # Validate if we have different settings for the same config on
        # different architecures, like having it as builtin on one and as a
        # module on a different arch.
        if len(configs.keys()) > 1:
            print(configs["y"])
            print(configs["m"])
            raise RuntimeError(f"{self.full_cs_name()}: Configuration mismatach between codestreams. Aborting.")

    def find_obj_path(self, arch, mod):
        # Return the path if the modules was previously found for ARCH, or refetch if
        # the obejct is for a different architecture
        obj = self.modules.get(mod, "")
        if obj:
            assert self.kernel in str(obj)
            return obj

        # We already know the path to vmlinux, so return it
        if not is_mod(mod):
            return self.get_boot_file("vmlinux", arch).relative_to(get_datadir(arch))

        # Module name use underscores, but the final module object uses hyphens.
        mod = mod.replace("_", "[-_]")

        mod_path = self.get_mod_path(arch)
        with open(Path(mod_path, "modules.order")) as f:
            obj_match = re.search(rf"([\w\/\-]+\/{mod}\.k?o)", f.read())
            if not obj_match:
                raise RuntimeError(f"{self.full_cs_name()}-{arch} ({self.kernel}): Module not found: {mod}")

        # modules.order will show the module with suffix .o, so make sure the extension.
        obj_path = mod_path/(PurePath(obj_match.group(1)).with_suffix(".ko"))
        # Make sure that the .ko file exists
        assert obj_path.exists(), f"Module {str(obj_path)} doesn't exists. Aborting"

        return obj_path.relative_to(get_datadir(arch))


    def lp_out_file(self, lp_name, fname):
        fpath = f'{str(fname).replace("/", "_").replace("-", "_")}'
        return f"{lp_name}_{fpath}"


    # Cache the symbols using the object path. It differs for each
    # codestream and architecture
    # Return all the symbols not found per arch/obj
    def __check_symbol(self, arch, mod, symbols, cache):
        name = self.full_cs_name()

        cache.setdefault(arch, {})
        cache[arch].setdefault(name, {})

        if not cache[arch][name].get(mod, ""):
            obj = get_datadir(arch)/self.find_obj_path(arch, mod)
            cache[arch][name][mod] = get_all_symbols_from_object(obj, True)

        ret = []

        for symbol in symbols:
            nsyms = cache[arch][name][mod].count(symbol)
            if nsyms == 0:
                ret.append(symbol)

            elif nsyms > 1:
                print(f"WARNING: {self.full_cs_name()}-{arch} ({self.kernel}): symbol {symbol} duplicated on {mod}")

            # If len(syms) == 1 means that we found a unique symbol, which is
            # what we expect, and nothing need to be done.

        return ret


    # This functions is used to check if the symbols exist in the module that
    # will be livepatched. In this case skip_on_host argument will be false,
    # meaning that we want the symbol to checked against all supported
    # architectures before creating the livepatches.
    #
    # It is also used when we want to check if a symbol externalized in one
    # architecture exists in the other supported ones. In this case skip_on_host
    # will be True, since we trust the decisions made by the extractor tool.
    def check_symbol_archs(self, lp_archs, mod, symbols, skip_on_host):
        cache = {}

        arch_sym = {}
        # Validate only architectures supported by the codestream
        for arch in self.archs:
            if arch == ARCH and skip_on_host:
                continue

            # Skip if the arch is not supported by the livepatch code
            if arch not in lp_archs:
                continue

            # Assign the not found symbols on arch
            syms = self.__check_symbol(arch, mod, symbols, cache)
            if syms:
                arch_sym[arch] = syms

        return arch_sym


    def check_file_exists(self, file):
        return file_exists_in_tag(self.kernel, file)

    def read_file(self, file):
        return read_file_in_tag(self.kernel, file)

