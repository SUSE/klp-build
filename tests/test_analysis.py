# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2026 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

import logging

from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib.kernel_tree import get_commit_body
from klpbuild.klplib.analysis import (
    __extract_functions,
    __get_arch_config,
    __analyse_cs_files,
    analyse_configs,
    analyse_kmodules,
    filter_unset_configs,
    filter_unsupported_kmodules,
)
from tests.utils import FakeCS


# ── __extract_functions (git-based) ───────────────────────────────────────────

def test_extract_functions_filters_context_only_signature():
    # cd8944eb25d7: adds net_shaper_hierarchy_rcu right before the existing,
    # unmodified net_shaper_ops. The trailing context for the first hunk
    # includes net_shaper_ops's signature but not its body -- the classic
    # false-positive shape that the filter must drop.
    diff = get_commit_body("cd8944eb25d7e595fba2cfe49404695e06d1f650",
                           "net/shaper/shaper.c")
    funcs = __extract_functions([diff])
    assert funcs == {
        "net_shaper_hierarchy_rcu",
        "net_shaper_lookup",
        "net_shaper_nl_get_dumpit",
    }


def test_extract_functions_handles_empty_input():
    assert __extract_functions([]) == set()
    assert __extract_functions([""]) == set()


def test_extract_functions_large_body():
    # 86b8cbd9915b: moves src_pad initialization below the NULL-check for
    # csidev->s_subdev inside stm32_csi_start. The -W hunk expands to the
    # full 134-line function body -- exercises depth tracking across a large
    # body with many inner blocks.
    diff = get_commit_body("86b8cbd9915b9209c747b5d7604c18da08556c65",
                           "drivers/media/platform/st/stm32/stm32-csi.c")
    funcs = __extract_functions([diff])
    assert funcs == {"stm32_csi_start"}


def test_extract_functions_merges_across_diffs():
    # Two separate commits touching different functions in the same file;
    # the results must be unioned.
    diff_a = get_commit_body("af9aa67aec100",
                             "net/ipv4/inet_connection_sock.c")
    diff_b = get_commit_body("49c47cc21b5b",
                             "net/tls/tls_main.c")
    funcs_a = __extract_functions([diff_a])
    funcs_b = __extract_functions([diff_b])
    funcs_ab = __extract_functions([diff_a, diff_b])
    assert funcs_ab == funcs_a | funcs_b


# ── __extract_functions (synthetic diffs) ─────────────────────────────────────

def test_extract_functions_single_modified_function():
    diff = (
        "@@ -1,5 +1,6 @@ void context(void)\n"
        " static int my_func(int x)\n"
        " {\n"
        "     int a = 1;\n"
        "+    int b = 2;\n"
        "     return a;\n"
        " }\n"
    )
    assert __extract_functions([diff]) == {"my_func"}


def test_extract_functions_unmodified_function():
    diff = (
        "@@ -1,5 +1,5 @@ void context(void)\n"
        " static int my_func(int x)\n"
        " {\n"
        "     int a = 1;\n"
        "     return a;\n"
        " }\n"
    )
    assert __extract_functions([diff]) == set()


def test_extract_functions_deletion_counts_as_modification():
    diff = (
        "@@ -1,6 +1,5 @@ void context(void)\n"
        " void cleanup(void)\n"
        " {\n"
        "-    old_call();\n"
        "     remaining();\n"
        " }\n"
    )
    assert __extract_functions([diff]) == {"cleanup"}


def test_extract_functions_nested_braces():
    diff = (
        "@@ -1,10 +1,11 @@ void context(void)\n"
        " void nested_func(void)\n"
        " {\n"
        "     if (cond) {\n"
        "+        do_something();\n"
        "         for (i = 0; i < n; i++) {\n"
        "             arr[i] = 0;\n"
        "         }\n"
        "     }\n"
        "     return;\n"
        " }\n"
    )
    assert __extract_functions([diff]) == {"nested_func"}


def test_extract_functions_added_function():
    diff = (
        "@@ -0,0 +1,4 @@\n"
        "+int new_func(int x)\n"
        "+{\n"
        "+    return x + 1;\n"
        "+}\n"
    )
    assert __extract_functions([diff]) == {"new_func"}


def test_extract_functions_multiple_only_modified_extracted():
    diff = (
        "@@ -1,12 +1,13 @@ void context(void)\n"
        " void func_a(void)\n"
        " {\n"
        "+    new_call();\n"
        " }\n"
        " \n"
        " void func_b(void)\n"
        " {\n"
        "     existing_call();\n"
        " }\n"
    )
    assert __extract_functions([diff]) == {"func_a"}


def test_extract_functions_hunk_boundary_after_modification():
    # Modification seen before @@ -- function should still be extracted.
    diff = (
        "@@ -1,5 +1,6 @@ void context(void)\n"
        " void partial(int x)\n"
        " {\n"
        "+    added_line();\n"
        "@@ -20,3 +21,3 @@ void other(void)\n"
    )
    assert __extract_functions([diff]) == {"partial"}


def test_extract_functions_hunk_boundary_no_modification():
    # Signature appears in context, then @@ before any change -- not extracted.
    diff = (
        "@@ -1,5 +1,6 @@ void context(void)\n"
        " void trailer(int x)\n"
        " {\n"
        "     unchanged();\n"
        "@@ -20,3 +21,3 @@ void other(void)\n"
    )
    assert __extract_functions([diff]) == set()


def test_extract_functions_balanced_braces_in_body():
    diff = (
        "@@ -1,8 +1,9 @@ void context(void)\n"
        " void braces(void)\n"
        " {\n"
        "+    log(\"start\");\n"
        "     if (a) {\n"
        "         while (b) {\n"
        "             c++;\n"
        "         }\n"
        "     }\n"
        " }\n"
    )
    assert __extract_functions([diff]) == {"braces"}


# ── __get_arch_config ─────────────────────────────────────────────────────────

def test_get_arch_config_existing():
    assert __get_arch_config({"x86_64": "m", "s390x": "y"}, "x86_64") == "m"


def test_get_arch_config_missing():
    assert __get_arch_config({"x86_64": "m"}, "ppc64le") == "n"


# ── filter_unset_configs ──────────────────────────────────────────────────────

def test_filter_unset_configs_removes_unset():
    cs_set = FakeCS({}, configs={"CONFIG_A": {"x86_64": "m"}})
    cs_unset = FakeCS({}, configs={"CONFIG_B": {}, "CONFIG_C": {}})
    cs_list = [cs_set, cs_unset]
    unset_cs, unset_conf = filter_unset_configs(cs_list)
    assert cs_unset in unset_cs
    assert cs_set not in unset_cs
    assert cs_unset not in cs_list
    assert cs_set in cs_list
    assert unset_conf == ["CONFIG_B", "CONFIG_C"]


def test_filter_unset_configs_keeps_all_set():
    cs = FakeCS({}, configs={"CONFIG_A": {"x86_64": "m"}})
    cs_list = [cs]
    unset_cs, unset_conf = filter_unset_configs(cs_list)
    assert not unset_cs
    assert not unset_conf
    assert cs in cs_list


def test_filter_unset_configs_skips_empty_configs():
    cs = FakeCS({}, configs={})
    cs_list = [cs]
    unset_cs, unset_conf = filter_unset_configs(cs_list)
    assert not unset_cs
    assert not unset_conf


def test_filter_unset_configs_deduplicates_conf_names():
    cs1 = FakeCS({}, cs_name="a", configs={"CONFIG_X": {}})
    cs2 = FakeCS({}, cs_name="b", configs={"CONFIG_X": {}})
    cs_list = [cs1, cs2]
    _, unset_conf = filter_unset_configs(cs_list)
    assert unset_conf == ["CONFIG_X"]


# ── filter_unsupported_kmodules ───────────────────────────────────────────────

def test_filter_unsupported_kmodules_removes_unsupported():
    cs = FakeCS({}, modules={"mod_a": False, "mod_b": False})
    cs_list = [cs]
    unset = filter_unsupported_kmodules(cs_list)
    assert cs in unset
    assert cs not in cs_list


def test_filter_unsupported_kmodules_keeps_supported():
    cs = FakeCS({}, modules={"mod_a": True})
    cs_list = [cs]
    unset = filter_unsupported_kmodules(cs_list)
    assert not unset
    assert cs in cs_list


def test_filter_unsupported_kmodules_clears_modules():
    cs = FakeCS({}, modules={"mod_a": True})
    cs_list = [cs]
    filter_unsupported_kmodules(cs_list)
    assert cs.modules == {}


def test_filter_unsupported_kmodules_skips_no_modules():
    cs = FakeCS({}, modules={})
    cs_list = [cs]
    unset = filter_unsupported_kmodules(cs_list)
    assert not unset
    assert cs in cs_list


# ── __analyse_cs_files ────────────────────────────────────────────────────────

def test_analyse_cs_files_populates_files():
    cs = Codestream("15.5u15", kernel="5.14.21-150500.55.68")
    diff = get_commit_body("49c47cc21b5b", "net/tls/tls_main.c")
    report = __analyse_cs_files(cs, {"net/tls/tls_main.c": [diff]})
    assert "net/tls/tls_main.c" in cs.files
    entry = cs.files["net/tls/tls_main.c"]
    assert entry["conf"]
    assert entry["module"]
    assert len(entry["symbols"]) > 0
    assert len(report) == 1


def test_analyse_cs_files_no_config_logs_warning(caplog):
    cs = Codestream("15.5u15", kernel="5.14.21-150500.55.68")
    with caplog.at_level(logging.WARNING):
        report = __analyse_cs_files(cs, {"include/linux/fake.h": [""]})
    assert "include/linux/fake.h" not in cs.files
    assert report == ["include/linux/fake.h:::"]


# ── analyse_configs ───────────────────────────────────────────────────────────

def test_analyse_configs_groups_by_config():
    cs1 = FakeCS(
        {"net.c": {"conf": "CONFIG_NET", "module": "net.o"}},
        cs_name="15.4u0",
        configs={"CONFIG_NET": {"x86_64": "m"}},
    )
    cs2 = FakeCS(
        {"net.c": {"conf": "CONFIG_NET", "module": "net.o"}},
        cs_name="15.5u0",
        configs={"CONFIG_NET": {"x86_64": "m"}},
    )
    report = analyse_configs([cs1, cs2])
    assert len(report) == 1
    key = list(report.keys())[0]
    assert key.startswith("CONFIG_NET:")
    assert cs1 in report[key]
    assert cs2 in report[key]


def test_analyse_configs_separates_different_archs():
    cs1 = FakeCS(
        {"net.c": {"conf": "CONFIG_NET", "module": "net.o"}},
        cs_name="15.4u0",
        configs={"CONFIG_NET": {"x86_64": "m"}},
    )
    cs2 = FakeCS(
        {"net.c": {"conf": "CONFIG_NET", "module": "net.o"}},
        cs_name="15.5u0",
        configs={"CONFIG_NET": {"x86_64": "y"}},
    )
    report = analyse_configs([cs1, cs2])
    assert len(report) == 2


def test_analyse_configs_no_duplicate_cs_in_report():
    cs = FakeCS(
        {"a.c": {"conf": "CONFIG_A", "module": "a.o"},
         "b.c": {"conf": "CONFIG_A", "module": "b.o"}},
        configs={"CONFIG_A": {"x86_64": "m"}},
    )
    report = analyse_configs([cs])
    key = list(report.keys())[0]
    assert report[key].count(cs) == 1


# ── analyse_kmodules ──────────────────────────────────────────────────────────

def test_analyse_kmodules_checks_module_support():
    cs = FakeCS(
        {"net.c": {"conf": "CONFIG_NET", "module": "net/core/net.o"}},
        configs={"CONFIG_NET": {"x86_64": "m"}},
        supported={"net/core/net.o": (True, False)},
    )
    report = analyse_kmodules([cs])
    assert "net/core/net.o" in cs.modules
    assert cs.modules["net/core/net.o"] is True
    assert len(report) == 1


def test_analyse_kmodules_skips_builtin():
    cs = FakeCS(
        {"net.c": {"conf": "CONFIG_NET", "module": "net/core/net.o"}},
        configs={"CONFIG_NET": {"x86_64": "y"}},
    )
    report = analyse_kmodules([cs])
    assert "net/core/net.o" not in cs.modules
    assert len(report) == 0


def test_analyse_kmodules_skips_already_tracked():
    cs = FakeCS(
        {"net.c": {"conf": "CONFIG_NET", "module": "net/core/net.o"}},
        configs={"CONFIG_NET": {"x86_64": "m"}},
        modules={"net/core/net.o": True},
    )
    report = analyse_kmodules([cs])
    assert len(report) == 0


def test_analyse_kmodules_warns_blacklisted(caplog):
    cs = FakeCS(
        {"drv.c": {"conf": "CONFIG_DRV", "module": "drivers/drv.o"}},
        configs={"CONFIG_DRV": {"x86_64": "m"}},
        supported={"drivers/drv.o": (False, True)},
    )
    with caplog.at_level(logging.WARNING):
        analyse_kmodules([cs])
    assert "not supported by klp-build" in caplog.text
