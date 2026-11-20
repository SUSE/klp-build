# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE

import logging
from pathlib import Path

from klpbuild.klplib import symbol_checker
from klpbuild.klplib.symbol_checker import ElfSymbolChecker


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
