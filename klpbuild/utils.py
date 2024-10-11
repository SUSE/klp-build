# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import gzip
import io
import platform

from elftools.common.utils import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import lzma
import zstandard


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

    return ret_list


def is_mod(mod):
    return mod != "vmlinux"


def get_elf_modinfo_entry(elffile, conf):
    sec = elffile.get_section_by_name(".modinfo")
    if not sec:
        return None

    # Iterate over all info on modinfo section
    for line in bytes2str(sec.data()).split("\0"):
        if line.startswith(conf):
            key, val = line.split("=")
            return val.strip()

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
