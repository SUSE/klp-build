# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE

import logging
import sys
import types
from pathlib import Path

import pytest

from klpbuild.klplib import symbol_checker
from klpbuild.klplib.symbol_checker import (ElfSymbolChecker, KlpDataSymbolChecker,
                                            SymbolCheckError, get_symbol_checker)


class FakeSymtab:
    def __init__(self, symbols):
        self.symbols = symbols

    def get_symbol_by_name(self, name):
        return self.symbols.get(name)


class FakeElf:
    def __init__(self, symbols):
        self.symtab = FakeSymtab(symbols)

    def get_section_by_name(self, name):
        return self.symtab


class FakeCS:
    kernel = "5.14.21-150400.24.1"

    def full_cs_name(self):
        return "15.4u0"

    def find_obj_path(self, arch, mod):
        return f"{mod}.ko"


def test_elf_missing_symbols(monkeypatch, caplog):
    elf = FakeElf({"present": [object()], "dup": [object(), object()]})
    monkeypatch.setattr(symbol_checker, "get_datadir", lambda arch=None: Path("/data"))
    monkeypatch.setattr(symbol_checker, "get_elf_object", lambda obj: elf)

    with caplog.at_level(logging.WARNING):
        missing = ElfSymbolChecker(FakeCS()).missing_symbols("x86_64", "vmlinux",
                                                              ["present", "dup", "absent"])

    assert missing == ["absent"]
    assert "symbol dup duplicated" in caplog.text
    assert "symbol present duplicated" not in caplog.text


class FakeKlpData:
    """Stands for both the klp_data module and the KlpData instance."""

    class TargetNotFoundError(KeyError):
        pass

    class ModuleNotFoundError(KeyError):
        pass

    def __init__(self, targets=("15.4u0",)):
        self.targets = targets
        # Only found with an explicit data_dir, like with KLP_DATA_DIR unset
        self.needs_data_dir = False
        self.data_dir = None

    def KlpData(self, data_dir=None):
        if self.needs_data_dir and data_dir is None:
            raise FileNotFoundError("symbols.db")
        self.data_dir = data_dir
        return self

    def get_sym(self, cs, arch, symbol, module=None, clones=False):
        if cs not in self.targets:
            raise self.TargetNotFoundError(cs)
        defs = {"present": 1, "dup": 2}.get(symbol, 0)
        return [types.SimpleNamespace(defined=True)] * defs

    def get_module(self, cs, arch, module):
        if cs not in self.targets:
            raise self.TargetNotFoundError(cs)
        return types.SimpleNamespace(supported=module != "unsupported")


@pytest.fixture
def klp_data(monkeypatch):
    fake = FakeKlpData()
    monkeypatch.delenv("KLPBUILD_NO_KLP_DATA")
    monkeypatch.setitem(sys.modules, "klp_data", fake)
    return fake


def test_klp_data_missing_symbols(klp_data, caplog):
    checker = get_symbol_checker(FakeCS())

    with caplog.at_level(logging.WARNING):
        missing = checker.missing_symbols("x86_64", "vmlinux", ["present", "dup", "absent"])

    assert missing == ["absent"]
    assert "symbol dup duplicated" in caplog.text


def test_klp_data_module_unsupported(klp_data):
    checker = get_symbol_checker(FakeCS())

    assert not checker.module_unsupported("x86_64", "fs/ext4/ext4")
    assert checker.module_unsupported("x86_64", "drivers/foo/unsupported")


def test_klp_data_unknown_target(klp_data):
    klp_data.targets = ()

    with pytest.raises(SymbolCheckError, match="klp-data sync 15.4u0"):
        get_symbol_checker(FakeCS()).missing_symbols("x86_64", "vmlinux", ["present"])


def test_klp_data_patchable_check_not_done(klp_data, caplog):
    with caplog.at_level(logging.WARNING):
        get_symbol_checker(FakeCS()).missing_symbols("x86_64", "vmlinux", ["present"], True)

    assert "can't check if the symbols can be livepatched" in caplog.text


def test_get_symbol_checker_prefers_klp_data(klp_data):
    assert isinstance(get_symbol_checker(FakeCS()), KlpDataSymbolChecker)


def test_get_symbol_checker_can_be_forced_to_elf(klp_data, monkeypatch):
    monkeypatch.setenv("KLPBUILD_NO_KLP_DATA", "1")

    assert isinstance(get_symbol_checker(FakeCS()), ElfSymbolChecker)


def test_get_symbol_checker_looks_for_symbols_db_in_data_dir(klp_data, monkeypatch):
    klp_data.needs_data_dir = True
    monkeypatch.setattr(symbol_checker, "get_datadir", lambda arch="": Path("/data"))

    assert isinstance(get_symbol_checker(FakeCS()), KlpDataSymbolChecker)
    assert klp_data.data_dir == "/data"
