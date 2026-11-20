# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE

import pytest

from klpbuild.klplib import symbol_checker


@pytest.fixture(autouse=True)
def elf_symbol_checker(monkeypatch):
    """
    Parse the ELF objects by default, so that the tests don't depend on the
    klp_data bindings and symbols.db being installed. The tests of the
    klp_data backend enable it explicitly.
    """
    monkeypatch.setenv("KLPBUILD_NO_KLP_DATA", "1")
    symbol_checker._checker_builder.cache_clear()
    yield
    symbol_checker._checker_builder.cache_clear()
