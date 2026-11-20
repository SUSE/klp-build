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

from abc import ABC, abstractmethod


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
