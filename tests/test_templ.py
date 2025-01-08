# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect

from klpbuild.extractor import Extractor
from klpbuild.setup import Setup
from klpbuild import utils
from tests.utils import get_file_content


def test_templ_with_externalized_vars():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u19"

    lp_setup = Setup(lp)
    ffuncs = Setup.setup_file_funcs("CONFIG_PROC_FS", "vmlinux", [
                                  ["fs/proc/cmdline.c", "cmdline_proc_show"]], [], [])

    codestreams = lp_setup.setup_codestreams(
        {"cve": None, "lp_filter": cs, "lp_skips": None, "conf": "CONFIG_PROC_FS", "no_check": False})

    lp_setup.setup_project_files(codestreams, ffuncs, utils.ARCHS)

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # As the code is using the default archs, which is all of them, the
    # IS_ENABLED macro shouldn't exist
    content = get_file_content(lp, cs)
    for check in ["LP_MODULE", "module_notify", "linux/module.h", "#if IS_ENABLED"]:
        assert check not in content

    # For this file and symbol, there is one symbol to be looked up, so
    # klp_funcs should be present
    assert "klp_funcs" in content


def test_templ_without_externalized_vars():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u19"

    lp_setup = Setup(lp)
    ffuncs = Setup.setup_file_funcs("CONFIG_IPV6", "vmlinux", [
                                  ["net/ipv6/rpl.c", "ipv6_rpl_srh_size"]], [], [])

    codestreams = lp_setup.setup_codestreams(
        {"cve": None, "lp_filter": cs, "lp_skips": None, "conf": "CONFIG_IPV6", "no_check": False})

    lp_setup.setup_project_files(codestreams, ffuncs, [utils.ARCH])

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # For this file and symbol, no externalized symbols are used, so
    # klp_funcs shouldn't be preset.
    content = get_file_content(lp, cs)
    for check in ["LP_MODULE", "module_notify", "linux/module.h", "klp_funcs"]:
        assert check not in content

    # As the config only targets one arch, IS_ENABLED should be set
    assert "#if IS_ENABLED" in content

    # Without CVE speficied, we should have XXXX-XXXX
    assert "CVE-XXXX-XXXX" in content


# For multifile patches, a third file will be generated and called
# livepatch_XXX, and alongside this file the other files will have the prefix
# bscXXXXXXX.
def test_check_header_file_included():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u17"

    lp_setup = Setup(lp)
    ffuncs = Setup.setup_file_funcs("CONFIG_IPV6", "vmlinux", [["net/ipv6/rpl.c", "ipv6_rpl_srh_size"],
                                                               ["kernel/events/core.c", "perf_event_exec"]],
                                    [], [])

    codestreams = lp_setup.setup_codestreams(
        {"cve": None, "lp_filter": cs, "lp_skips": None, "conf": "CONFIG_IPV6", "no_check": False})

    lp_setup.setup_project_files(codestreams, ffuncs, utils.ARCHS)

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    # test the livepatch_ prefix file
    assert "Upstream commit:" in get_file_content(lp, cs)

    # Check for all supported codestreams
    for item in ["SLE12-SP5", "SLE15-SP2 and -SP3", "SLE15-SP4 and -SP5",
                 "SLE15-SP6", "SLE MICRO-6-0"]:
        assert item in get_file_content(lp, cs)

    # Check the other two files
    assert "Upstream commit:" not in get_file_content(lp, cs, f"{lp}_kernel_events_core.c")
    assert "Upstream commit:" not in get_file_content(lp, cs, f"{lp}_net_ipv6_rpl.c")


def test_templ_cve_specified():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u19"

    lp_setup = Setup(lp)
    ffuncs = Setup.setup_file_funcs("CONFIG_PROC_FS", "vmlinux", [
                                  ["fs/proc/cmdline.c", "cmdline_proc_show"]], [], [])

    codestreams = lp_setup.setup_codestreams(
        {"cve": "1234-5678", "lp_filter": cs, "lp_skips": None, "conf": "CONFIG_PROC_FS", "no_check": True})

    lp_setup.setup_project_files(codestreams, ffuncs, utils.ARCHS)

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    # With CVE speficied, we should have it in the final file
    assert "CVE-1234-5678" in get_file_content(lp, cs)


def test_templ_exts_mod_name():
    """
    This extraction should add a new external symbol from module nvme-core, but the kallsyms relocation
    need the module to be nvme_core.
    """
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "12.5u56"

    lp_setup = Setup(lp)
    ffuncs = Setup.setup_file_funcs("CONFIG_NVME_TCP", "nvme-tcp", [
                                  ["drivers/nvme/host/tcp.c", "nvme_tcp_io_work"]], [], [])

    codestreams = lp_setup.setup_codestreams(
        {"cve": None, "lp_filter": cs, "lp_skips": None, "conf": "CONFIG_NVME_TCP", "no_check": True})

    lp_setup.setup_project_files(codestreams, ffuncs, utils.ARCHS)

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    # The module name should be nvme_core instead of nvme-core
    assert '{ "nvme_should_fail", (void *)&klpe_nvme_should_fail, "nvme_core" },' in get_file_content(lp, cs)


def test_templ_micro_is_ibt():
    """
    SLE Micro is based on kernel 6.4, make sure it uses IBT.
    """
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "6.0u2"

    lp_setup = Setup(lp)
    ffuncs = Setup.setup_file_funcs("CONFIG_NVME_TCP", "nvme-tcp", [
                                  ["drivers/nvme/host/tcp.c", "nvme_tcp_io_work"]], [], [])

    codestreams = lp_setup.setup_codestreams(
        {"cve": None, "lp_filter": cs, "lp_skips": None, "conf": "CONFIG_NVME_TCP", "no_check": True})

    lp_setup.setup_project_files(codestreams, ffuncs, utils.ARCHS)

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[]).run()

    assert 'KLP_RELOC_SYMBOL' in get_file_content(lp, cs)
