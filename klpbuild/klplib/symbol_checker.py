# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE

"""
Symbol and module checks against the kernel objects of a codestream.

``klpbuild`` needs to answer a few questions about the kernel binaries of a
codestream: does a symbol exist in vmlinux or in a given module, is a module
supported, ... :class:`SymbolChecker` defines those questions, so that the
answer can come from different sources without the callers having to care.
"""

import bisect
import logging
import sys
from abc import ABC, abstractmethod

from klpbuild.klplib.affected_file import AffectedModule
from klpbuild.klplib.utils import (check_module_unsupported, get_all_symbols_from_object,
                                   get_datadir, get_elf_object)


class SymbolCheckError(RuntimeError):
    """The requested codestream, arch or module could not be looked up."""


class SymbolChecker(ABC):
    """
    Answer symbol and module queries for one codestream.

    A codestream, arch or module that cannot be looked up must be reported
    with an exception, never as a symbol that is not present.
    :class:`SymbolCheckError` is the exception to use for that.
    """

    def __init__(self, cs):
        # The :class:`Codestream` the queries refer to.
        self.cs = cs

    @abstractmethod
    def missing_symbols(self, arch, mod, symbols, check_patchable=False):
        """
        Return the symbols of ``symbols`` that are not found in ``mod``.

        ``mod`` is the bare name of the object (``"vmlinux"`` or a module name
        like ``"fs/ext4/ext4"``). A symbol defined more than once in the object
        is found, but a warning is logged. When ``check_patchable`` is set,
        implementations that are able to must also verify that the symbols of
        vmlinux can be traced, and therefore livepatched.
        """

    @abstractmethod
    def module_unsupported(self, arch, mod):
        """Return True if the module ``mod`` is not supported by SLE."""

    @abstractmethod
    def missing_in_vmlinux(self, arch, symbols):
        """Return the symbols of ``symbols`` that are not defined in vmlinux."""


class ElfSymbolChecker(SymbolChecker):
    """Answer the queries by parsing the kernel objects with pyelftools."""

    def __check_patchable_sym(self, arch, name, sym, trace_addrs):
        val = sym["st_value"]

        # For IBT enabled kernels, some functions might have ENDBR instructions
        # at the first offset of the symbol. To make the check catch all cases,
        # always check for the trace addr and also the same trace addr - 4, to
        # match the symbol table on functions that don't have the IBT enabled.
        for val in [sym["st_value"], sym["st_value"] + 4]:
            pos = bisect.bisect_left(trace_addrs, val)

            # Check if the symbol was found
            if pos != len(trace_addrs) and trace_addrs[pos] == val:
                return

        logging.error("%s-%s (%s): Symbol %s has tracing disabled.", self.cs.full_cs_name(), arch, self.cs.kernel, name)
        sys.exit(1)

    # On ppc64le the trace_address points to symbol descriptor table, and not
    # the symbol itself, so we need to check for the address range
    def __check_patchable_sym_ppc64le(self, arch, name, sym, trace_addrs):
        code_start = sym["st_value"]
        code_end = code_start + sym["st_size"]

        pos = bisect.bisect_left(trace_addrs, code_start)
        if pos == len(trace_addrs) or trace_addrs[pos] > code_end:
            logging.error("%s-%s (%s): Symbol %s has tracing disabled.",  self.cs.full_cs_name(),
                          arch, self.cs.kernel, name)
            sys.exit(1)

    def __get_trace_addresses(self, arch, elf_obj):
        # Get all addresses related to the functions that can be traced/livepatched
        # and populate an array for later inspection
        symtab = elf_obj.get_section_by_name(".symtab")

        start_mcount = symtab.get_symbol_by_name("__start_mcount_loc")[0]
        stop_mcount = symtab.get_symbol_by_name("__stop_mcount_loc")[0]

        sec = elf_obj.get_section(start_mcount["st_shndx"])

        start = start_mcount["st_value"] - sec["sh_addr"]
        stop = stop_mcount["st_value"] - sec["sh_addr"]

        order = "big" if arch == "s390x" else "little"

        sec_data = sec.data()[start:stop]
        syms = []

        for i in range(0, len(sec_data), 8):
            ptr = sec_data[i:i+8]

            data = int.from_bytes(ptr, byteorder=order)
            if data > 0:
                syms.append(data)

        syms.sort()

        return syms

    # Return all the symbols not found per arch/obj
    def missing_symbols(self, arch, mod, symbols, check_patchable=False):
        ret = []

        obj = get_datadir(arch) / self.cs.find_obj_path(arch, mod)
        elf_obj = get_elf_object(obj)

        trace_addrs = []

        # Get the addresses of the traceable objects on vmlinux
        if mod == AffectedModule.VMLINUX and check_patchable:
            trace_addrs = self.__get_trace_addresses(arch, elf_obj)

        symtab = elf_obj.get_section_by_name(".symtab")

        for symbol in symbols:
            syms = symtab.get_symbol_by_name(symbol)
            # can return None is the symbol is not found, or a list if the symbol
            # is not unique
            if not syms:
                ret.append(symbol)
                continue

            if len(syms) > 1:
                logging.warning("%s-%s (%s): symbol %s duplicated on %s", self.cs.full_cs_name(), arch, self.cs.kernel, symbol, mod)

            # If len(syms) == 1 means that we found a unique symbol, which is
            # what we expect

            # Check if the symbol itself can be traced. There are cases where
            # the symbol is found, but it was instructed to not be possible
            # to trace, so we can't livepatch it either
            # For now only check this on vmlinux. The support for modules
            # required applying relocation, which is far more complicated.
            #
            # This method is called on setup and extraction phase, but check
            # is only necessary for setup, since the extractor knows if a symbol
            # is traceable or not.
            #
            # TODO: implement support for modules as well
            if trace_addrs:
                # The symbol is unique, so we can grab the first entry safely
                # TODO: missing support for aarch64
                if arch in ["x86_64", "s390x"]:
                    self.__check_patchable_sym(arch, symbol, syms[0], trace_addrs)

                elif arch in ["ppc64le"]:
                    self.__check_patchable_sym_ppc64le(arch, symbol, syms[0], trace_addrs)

        return ret

    def module_unsupported(self, arch, mod):
        mod_path = self.cs.find_obj_path(arch, mod)

        # Validate if the module being livepatched is supported or not
        return check_module_unsupported(arch, mod_path)

    def missing_in_vmlinux(self, arch, symbols):
        vmlinux_path = get_datadir(arch) / self.cs.find_obj_path(arch, AffectedModule.VMLINUX)
        vmlinux_syms = get_all_symbols_from_object(vmlinux_path, True)

        missing_syms = []
        for sym in symbols:
            if sym not in vmlinux_syms:
                missing_syms.append(sym)

        return missing_syms


def get_symbol_checker(cs):
    """Return the :class:`SymbolChecker` to use for the codestream ``cs``."""
    return ElfSymbolChecker(cs)
