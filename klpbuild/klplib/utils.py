# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import copy
import git
import gzip
import io
import logging
import lzma
import platform
import re
import zstandard

from elftools.common.utils import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import PurePath

from natsort import natsorted

from klpbuild.klplib.config import get_user_path

ARCH = platform.processor()
ARCHS = ["ppc64le", "s390x", "x86_64"]


# Group all codestreams that share code in a format like bellow:
#   [15.2u10 15.2u11 15.3u10 15.3u12 ]
# Will be converted to:
#   15.2u10-11 15.3u10 15.3u12
# The returned value will be a list of lists, each internal list will
# contain all codestreams which share the same code
def classify_codestreams(cs_list):
    # Group all codestreams that share the same codestream by a new dict
    # divided by the SLE version alone, making it easier to process
    # later
    cs_group = {}
    for cs in cs_list:
        if not isinstance(cs, str):
            cs = cs.name()

        prefix, up = cs.split("u")
        if not cs_group.get(prefix, ""):
            cs_group[prefix] = [int(up)]
        else:
            cs_group[prefix].append(int(up))

    ret_list = []
    for cs, ups in cs_group.items():
        if len(ups) == 1:
            ret_list.append(f"{cs}u{ups[0]}")
            continue

        sim = []
        while len(ups):
            if not sim:
                sim.append(ups.pop(0))
                continue

            cur = ups.pop(0)
            last_item = sim[len(sim) - 1]
            if last_item + 1 <= cur:
                sim.append(cur)
                continue

            # they are different, print them
            if len(sim) == 1:
                ret_list.append(f"{cs}u{sim[0]}")
            else:
                ret_list.append(f"{cs}u{sim[0]}-{last_item}")

            sim = [cur]

        # Loop finished, check what's in similar list to print
        if len(sim) == 1:
            ret_list.append(f"{cs}u{sim[0]}")
        elif len(sim) > 1:
            last_item = sim[len(sim) - 1]
            ret_list.append(f"{cs}u{sim[0]}-{last_item}")

    return natsorted(ret_list)


def classify_codestreams_str(cs_list):
    return " ".join(classify_codestreams(cs_list))


def is_mod(mod):
    return mod != "vmlinux"


def get_elf_modinfo_entry(elffile, conf):
    sec = elffile.get_section_by_name(".modinfo")
    if not sec:
        return None

    # Iterate over all info on modinfo section
    for line in bytes2str(sec.data()).split("\0"):
        if line.startswith(conf):
            return line.split("=")[1].strip()

    return ""


def get_elf_object(obj):
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
def get_all_symbols_from_object(obj, defined):
    syms = []

    for sec in get_elf_object(obj).iter_sections():
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


def get_lp_branches(lp_name, git_dir):
    branches = []

    # Filter only the branches related to this BSC
    for r in git.Repo(git_dir).branches:
        if r.name.startswith(lp_name):
            branches.append(r.name)

    return branches


def get_cs_branch(cs, lp_name, git_dir):
    branch_name = ""

    for branch in get_lp_branches(lp_name, git_dir):
        # Check if the codestream is a rt one, and if yes, apply the correct
        # separator later on
        if cs.rt and "rt" not in branch:
            continue

        separator = "u"
        if cs.rt:
            separator = "rtu"

        # First check if the branch has more than code stream sharing
        # the same code
        for b in branch.replace(lp_name + "_", "").split("_"):
            # Only check the branches that are the same type of the branch
            # being searched. Only check RT branches if the codestream is a
            # RT one.
            if cs.rt and "rtu" not in b:
                continue

            if not cs.rt and "rtu" in b:
                continue

            sle, u = b.split(separator)
            if f"{cs.sle}.{cs.sp}" != f"{sle}":
                continue

            # Get codestreams interval
            up = u
            down = u
            if "-" in u:
                down, up = u.split("-")

            # Codestream between the branch codestream interval
            if cs.update >= int(down) and cs.update <= int(up):
                branch_name = branch
                break

            # At this point we found a match for our codestream in
            # codestreams.json, but we may have a more specialized git
            # branch later one, like:
            # bsc1197597_12.4u21-25_15.0u25-28
            # bsc1197597_15.0u25-28
            # Since 15.0 SLE uses a different kgraft-patches branch to
            # be built on. In this case, we continue to loop over the
            # other branches.

    return branch_name


def check_module_unsupported(arch, mod_path):
    elffile = get_elf_object(get_datadir(arch)/mod_path)
    return "no" == get_elf_modinfo_entry(elffile, "supported")


def filter_codestreams(lp_filter, cs_list, verbose=False):
    if isinstance(cs_list, dict):
        full_cs = copy.deepcopy(list(cs_list.values()))
    else:
        full_cs = copy.deepcopy(cs_list)

    if verbose:
        logging.info("Checking filter...")

    result = []
    filtered = []
    for cs in full_cs:
        name = cs.name()

        if lp_filter and not re.match(lp_filter, name):
            filtered.append(name)
            continue

        result.append(cs)

    if verbose:
        if filtered:
            logging.info("Skipping codestreams:")
            logging.info("\t%s", classify_codestreams_str(filtered))

    return result

def get_mail():
    git_data = git.GitConfigParser()
    user = git_data.get_value("user", "name")
    email = git_data.get_value("user", "email")

    return user, email

def fix_mod_string(mod):
    if not is_mod(mod):
        return ""

    # Modules like snd-pcm needs to be replaced by snd_pcm in LP_MODULE
    # and in kallsyms lookup
    return mod.replace("-", "_")


def get_kgraft_branch(cs_name):
    if "6.0" in cs_name:
        branch = "MICRO-6-0"

        if "rt" in cs_name:
            branch = branch + "-RT"

        _, update = cs_name.split("u")
        return f"{branch}_Update_{update}"

    if '12.' in cs_name:
        return "master-livepatch-sle12"

    if '15.3' in cs_name:
        return "master-livepatch"

    if "15.4" in cs_name or "15.5" in cs_name:
        return "master-livepatch-sle15sp4"

    return "master-livepatch-sle15sp6"


def get_workdir(lp_name):
    """
    Get the working directory for a given livepatch name.

    Args:
        lp_name (str): The name of the livepatch.

    Returns:
        Path: The full path to the livepatch file.
    """
    return get_user_path('work_dir')/lp_name


def get_datadir(arch=""):
    """
    Get the data directory.

    Returns:
        Path: The full path to the livepatch file.
    """
    if arch:
        assert arch in ARCHS
    data_dir = get_user_path('data_dir')
    return data_dir/arch if arch else data_dir


def get_tests_path(lp_name):
    """
    Retrieves the path of the test script associated with a given live patch name.

    Args:
        lp_name (str): The live patch name to search for the test script.

    Raises:
        RuntimeError: If no test script is found.

    Returns:
        Path: The path to the test script or directory containing it.
    """
    kgr_path = get_user_path('kgr_patches_tests_dir')

    test_sh = kgr_path/(lp_name+"_test_script.sh")
    if test_sh.is_file():
        return test_sh

    test_dir_sh = kgr_path/lp_name/"test_script.sh"
    if test_dir_sh.is_file():
        # For more complex tests we support using a directory containing
        # as much files as needed. A `test_script.sh` is still required
        # as an entry point.
        return PurePath(test_dir_sh).parent

    raise RuntimeError(f"Couldn't find {test_sh} or {test_dir_sh}")
