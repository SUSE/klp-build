# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from pathlib import Path, PurePath
import re

from klpbuild.klplib.utils import ARCH, is_mod, get_all_symbols_from_object, get_datadir

class Codestream:
    __slots__ = ("data_path", "lp_path", "lp_name", "sle", "sp", "update", "rt",
                 "ktype", "needs_ibt", "is_micro", "project", "patchid", "kernel",
                 "archs", "files", "modules", "repo")

    def __init__(self, data_path, lp_path, sle, sp, update, rt, project,
                 patchid, kernel, archs, files, modules):
        self.data_path = data_path
        self.lp_path = lp_path
        self.lp_name = PurePath(lp_path).name
        self.sle = sle
        self.sp = sp
        self.update = update
        self.rt = rt
        self.ktype = "-rt" if rt else "-default"
        self.is_micro = sle == 6
        self.needs_ibt = self.is_micro or sle > 15 or (sle == 15 and sp >= 6)
        self.project = project
        self.patchid = patchid
        self.kernel = kernel
        self.archs = archs
        self.files = files
        self.modules = modules
        self.repo = self.get_repo()

    @classmethod
    def from_codestream(cls, data_path, lp_path, cs, proj, patchid, kernel):
        # Parse SLE15-SP2_Update_25 to 15.2u25
        rt = "rt" if "-RT" in cs else ""
        sp = "0"
        u = "0"

        # SLE12-SP5_Update_51
        if "SLE" in cs:
            sle, _, u = cs.replace("SLE", "").replace("-RT", "").split("_")
            if "-SP" in sle:
                sle, sp = sle.split("-SP")

        # MICRO-6-0_Update_2
        elif "MICRO" in cs:
            sle, sp, u = cs.replace("MICRO-", "").replace("-RT", "").replace("_Update_", "-").split("-")

        return cls(data_path, lp_path, int(sle), int(sp), int(u), rt, proj, patchid, kernel, [], {}, {})


    @classmethod
    def from_cs(cls, cs):
        match = re.search(r"(\d+)\.(\d+)(rt)?u(\d+)", cs)
        return cls("", "", int(match.group(1)), int(match.group(2)),
                   int(match.group(4)), match.group(3), "", "", "", [], {}, {})


    @classmethod
    def from_data(cls, data):
        return cls(data["data_path"], data["lp_path"], data["sle"], data["sp"],
                   data["update"], data["rt"], data["project"], data["patchid"],
                   data["kernel"], data["archs"], data["files"], data["modules"])


    def __eq__(self, cs):
        return self.sle == cs.sle and \
                self.sp == cs.sp and \
                self.update == cs.update and \
                self.rt == cs.rt


    def get_src_dir(self, arch=ARCH):
        # Only -rt codestreams have a suffix for source directory
        ktype = self.ktype.replace("-default", "")
        return get_datadir(arch)/"usr"/"src"/f"linux-{self.kernel}{ktype}"


    def get_obj_dir(self):
        return Path(f"{self.get_src_dir(ARCH)}-obj", ARCH, self.ktype.replace("-", ""))


    def get_ipa_file(self, fname):
        return Path(self.get_obj_dir(), f"{fname}.000i.ipa-clones")

    def get_boot_file(self, file, arch=ARCH):
        assert file.startswith("vmlinux") or file.startswith("config") or file.startswith("symvers")
        if self.is_micro:
            return Path(self.get_mod_path(arch), file)

        # Strip the suffix from the filename so we can add the kernel version in the middle
        fname = f"{Path(file).stem}-{self.kname()}{Path(file).suffix}"
        return get_datadir(arch)/"boot"/fname

    def get_repo(self):
        if self.update == 0 or self.is_micro:
            return "standard"

        repo = f"SUSE_SLE-{self.sle}"
        if self.sp != 0:
            repo = f"{repo}-SP{self.sp}"

        repo = f"{repo}_Update"

        # On 15.5 the RT kernels and in the main codestreams
        if not self.rt or (self.sle == 15 and self.sp == 5):
            return repo

        return f"{repo}_Products_SLERT_Update"

    def set_archs(self):
        # RT is supported only on x86_64 at the moment
        if self.rt:
            self.archs = ["x86_64"]

        # MICRO 6.0 doest support ppc64le
        elif "6.0" in self.name():
            self.archs = ["x86_64", "s390x"]

        # We support all architecture for all other codestreams
        else:
            self.archs = ["x86_64", "s390x", "ppc64le"]

    def set_files(self, files):
        self.files = files


    def kname(self):
        return self.kernel + self.ktype


    def name(self):
        if self.rt:
            return f"{self.sle}.{self.sp}rtu{self.update}"

        return f"{self.sle}.{self.sp}u{self.update}"


    def get_ccp_dir(self):
        """
        Get the path to the ccp directory of the current codestream.

        Returns:
            Path: The path to the ccp directory of the current codestream.
        """
        return Path(self.lp_path, "ccp", self.name())


    def lpdir(self):
        return self.get_ccp_dir()/"lp"


    def work_dir(self, fname):
        fpath = f'work_{str(fname).replace("/", "_")}'
        return self.get_ccp_dir()/fpath


    def name_cs(self):
        if self.rt:
            return f"{self.sle}.{self.sp}rt"
        return f"{self.sle}.{self.sp}"

    def name_full(self):
        # Parse 15.2u25 to SLE15-SP2_Update_25
        # Parse 6.0u2 to MICRO
        if self.is_micro:
            buf = f"MICRO-{self.sle}-{self.sp}"
        else:
            buf = f"SLE{self.sle}"
            if int(self.sp) > 0:
                buf = f"{buf}-SP{self.sp}"

        if self.rt:
            buf = f"{buf}-RT"

        return f"{buf}_Update_{self.update}"


    # 15.4 onwards we don't have module_mutex, so template generates
    # different code
    def is_mod_mutex(self):
        return not self.is_micro and (self.sle < 15 or (self.sle == 15 and self.sp < 4))

    def get_mod_path(self, arch):
        # Micro already has support for usrmerge
        if self.is_micro:
            mod_path = Path("usr", "lib")
        else:
            mod_path = Path("lib")

        return get_datadir(arch)/mod_path/"modules"/self.kname()

    # A codestream can be patching multiple objects, so get the path related to
    # the module that we are interested
    def get_mod(self, mod):
        return self.modules[mod]


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
            kconf = self.get_boot_file("config", arch)
            with open(kconf) as f:
                match = re.search(rf"{conf}=([ym])", f.read())
                if match:
                    configs[arch] = match.group(1)

        return configs


    def validate_config(self, conf, mod):
        configs = {}

        # Validate only the specified architectures, but check if the codestream
        # is supported on that arch (like RT that is currently supported only on
        # x86_64)
        for arch, conf_entry in self.get_all_configs(conf).items():
            if conf_entry == "m" and mod == "vmlinux":
                raise RuntimeError(f"{self.name()}:{arch} ({self.kernel}): Config {conf} is set as module, but no module was specified")
            if conf_entry == "y" and mod != "vmlinux":
                raise RuntimeError(f"{self.name()}:{arch} ({self.kernel}): Config {conf} is set as builtin, but a module {mod} was specified")

            configs.setdefault(conf_entry, [])
            configs[conf_entry].append(f"{self.name()}:{arch}")

        # Validate if we have different settings for the same config on
        # different architecures, like having it as builtin on one and as a
        # module on a different arch.
        if len(configs.keys()) > 1:
            print(configs["y"])
            print(configs["m"])
            raise RuntimeError(f"{self.name()}: Configuration mismatach between codestreams. Aborting.")


    # Return only the name of the module to be livepatched
    def find_obj_path(self, arch, mod):
        # Return the path is the modules was previously found
        obj = self.modules.get(mod, "")
        if obj:
            assert self.kernel in str(obj)
            return obj

        # We already know the path to vmlinux, so return it
        if not is_mod(mod):
            return self.get_boot_file("vmlinux", arch)

        # Module name use underscores, but the final module object uses hyphens.
        mod = mod.replace("_", "[-_]")

        mod_path = self.get_mod_path(arch)
        with open(Path(mod_path, "modules.order")) as f:
            obj_match = re.search(rf"([\w\/\-]+\/{mod}.k?o)", f.read())
            if not obj_match:
                raise RuntimeError(f"{self.name()}-{arch} ({self.kernel}): Module not found: {mod}")

        # modules.order will show the module with suffix .o, so
        # make sure the extension. Also check for multiple extensions since we
        # can have modules being compressed using different algorithms.
        for ext in [".ko", ".ko.zst", ".ko.gz"]:
            obj = str(PurePath(obj_match.group(1)).with_suffix(ext))
            if Path(mod_path, obj).exists():
                break

        return Path(mod_path, obj)


    def lp_out_file(self, fname):
        fpath = f'{str(fname).replace("/", "_").replace("-", "_")}'
        return f"{self.lp_name}_{fpath}"


    # Cache the symbols using the object path. It differs for each
    # codestream and architecture
    # Return all the symbols not found per arch/obj
    def __check_symbol(self, arch, mod, symbols, cache):
        name = self.name()

        cache.setdefault(arch, {})
        cache[arch].setdefault(name, {})

        if not cache[arch][name].get(mod, ""):
            obj = self.find_obj_path(arch, mod)
            cache[arch][name][mod] = get_all_symbols_from_object(obj, True)

        ret = []

        for symbol in symbols:
            nsyms = cache[arch][name][mod].count(symbol)
            if nsyms == 0:
                ret.append(symbol)

            elif nsyms > 1:
                print(f"WARNING: {self.name()}-{arch} ({self.kernel}): symbol {symbol} duplicated on {mod}")

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


    def data(self):
        return {
                "sle" : self.sle,
                "sp" : self.sp,
                "update" : self.update,
                "rt" : self.rt,
                "project" : self.project,
                "patchid": self.patchid,
                "kernel" : self.kernel,
                "archs" : self.archs,
                "files" : self.files,
                "modules" : self.modules,
                "repo" : self.repo,
                "data_path" : str(self.data_path),
                "lp_path" : str(self.lp_path),
                "lp_name" : str(self.lp_name),
                }
