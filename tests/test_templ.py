# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect

from klpbuild.klplib import utils
from klpbuild.plugins.extract import extract
from klpbuild.plugins.setup import setup
from tests.utils import get_file_content


def test_templ_with_externalized_vars():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u19"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": False,
        "archs" : utils.ARCHS,
        "cve": None,
        "conf": "CONFIG_PROC_FS",
        "module" : "vmlinux",
        "file_funcs" : [["fs/proc/cmdline.c", "cmdline_proc_show"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[])

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # As the code is using the default archs, which is all of them, the
    # IS_ENABLED macro shouldn't exist
    # the include of livepatch.h should not be present because 15.5 doesn't use IBT
    content = get_file_content(lp, cs)
    for check in ["LP_MODULE", "module_notify", "linux/module.h", "#if IS_ENABLED", "linux/livepatch.h"]:
        assert check not in content

    # For this file and symbol, there is one symbol to be looked up, so
    # klp_funcs should be present
    assert "klp_funcs" in content

    # With external symbols but only from vmlinux, so we have _init don't we don't need an _exit
    # Also, as it's enabled on all ARCHs we don't need the ENABLED checks
    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "_init(void);" in header
    assert "_init(void) { return 0; }" not in header
    assert "_cleanup(void);" not in header
    assert "_cleanup(void) {}" in header
    assert "IS_ENABLED" not in header


def test_templ_without_externalized_vars():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u19"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": False,
        "archs" : [utils.ARCH],
        "cve": None,
        "conf": "CONFIG_IPV6",
        "module" : "vmlinux",
        "file_funcs" : [["net/ipv6/rpl.c", "ipv6_rpl_srh_size"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[])

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # For this file and symbol, no externalized symbols are used, so
    # klp_funcs shouldn't be preset.
    # the include of livepatch.h should not be present because 15.5 doesn't use IBT
    content = get_file_content(lp, cs)
    for check in ["LP_MODULE", "module_notify", "linux/module.h", "klp_funcs", "linux/livepatch.h>"]:
        assert check not in content

    # As the config only targets one arch, IS_ENABLED should be set
    assert "#if IS_ENABLED" in content

    # Without CVE speficied, we should have XXXX-XXXX
    assert "CVE-XXXX-XXXX" in content

    # Without external symbols we don't need to implement the _init/_exit functions
    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "_init(void);" not in header
    assert "_init(void) { return 0; }" in header
    assert "_cleanup(void);" not in header
    assert "_cleanup(void) {}" in header
    assert "IS_ENABLED" not in header


# For multifile patches, a third file will be generated and called
# livepatch_XXX, and alongside this file the other files will have the prefix
# bscXXXXXXX.
def test_check_header_file_included():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u17"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": False,
        "archs" : utils.ARCHS,
        "cve": None,
        "conf": "CONFIG_IPV6",
        "module" : "vmlinux",
        "file_funcs" : [["net/ipv6/rpl.c", "ipv6_rpl_srh_size"],
                        ["kernel/events/core.c", "perf_event_exec"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)


    extract(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[])

    # test the livepatch_ prefix file
    assert "Upstream commit:" in get_file_content(lp, cs)

    # Check for all supported codestreams
    for item in ["SLE12-SP5", "SLE15-SP3", "SLE15-SP4 and -SP5",
                 "SLE15-SP6", "SLE MICRO-6-0"]:
        assert item in get_file_content(lp, cs)

    # Check the other two files
    assert "Upstream commit:" not in get_file_content(lp, cs, f"{lp}_kernel_events_core.c")
    assert "Upstream commit:" not in get_file_content(lp, cs, f"{lp}_net_ipv6_rpl.c")

    # Check that for file kernel/events/core.c there are externalized symbols, so the prototype
    # of init/cleanup are created on header
    # As net/ipv6/rpl.c there are no externalized symbols we expect that it's prototype isn't
    # created on livepatch_header file
    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "kernel_events_core_init(void);" in header
    assert "kernel_events_core_cleanup(void);" in header
    assert "net_ipv6_rpl" not in header


def test_templ_cve_specified():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u19"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": True,
        "archs" : [utils.ARCH],
        "cve": "1234-5678",
        "conf": "CONFIG_PROC_FS",
        "module" : "vmlinux",
        "file_funcs" : [["fs/proc/cmdline.c", "cmdline_proc_show"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[])

    # With CVE speficied, we should have it in the final file
    assert "CVE-1234-5678" in get_file_content(lp, cs)

    # This livepatch targets only the running platform, so the IS_ENABLED needs to be there
    # And with it, both prototypes and empty functions needs to be there. The _cleanup is a
    # prototype of the IS_ENABLED path is only a prototype because the symbol is from vmlinux
    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "_init(void);" in header
    assert "_init(void) { return 0; }" in header
    assert "_cleanup(void) {}" in header
    assert "IS_ENABLED" in header


def test_templ_exts_mod_name():
    """
    This extraction should add a new external symbol from module nvme-tcp, but the kallsyms relocation
    need the module to be nvme_tcp.
    """
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.3u42"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": True,
        "archs" : utils.ARCHS,
        "cve": None,
        "conf": "CONFIG_NVME_TCP",
        "module" : "nvme-tcp",
        "file_funcs" : [["drivers/nvme/host/tcp.c", "nvme_tcp_io_work"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[])

    # The module name should be nvme_tcp instead of nvme-tcp
    assert '{ "nvme_tcp_try_send", (void *)&klpe_nvme_tcp_try_send, "nvme_tcp" },' in get_file_content(lp, cs)

    # With external symbols from a module we expect both _init/_cleanup to be prototypes, since
    # the livepatch lookup will have a notifier for the module, and the notifier needs to be removed on
    # _cleanup path.
    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "_init(void);" in header
    assert "_init(void) { return 0; }" not in header
    assert "_cleanup(void);" in header
    assert "_cleanup(void) {}" not in header
    # IS_ENABLED should not be present because the LP is targetted to all codestreams.
    assert "IS_ENABLED" not in header


def test_templ_micro_is_ibt():
    """
    SLE Micro is based on kernel 6.4, make sure it uses IBT.
    For IBT we don't need to use kallsyms, so the _init and _cleanup should be empty;
    """
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "6.0u2"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": True,
        "archs" : utils.ARCHS,
        "cve": None,
        "conf": "CONFIG_NVME_TCP",
        "module" : "nvme-tcp",
        "file_funcs" : [["drivers/nvme/host/tcp.c", "nvme_tcp_io_work"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)


    extract(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[])

    src = get_file_content(lp, cs)
    # Requires the include since it's a codestream that uses IBT and has externalized symbols
    assert 'include <linux/livepatch.h>' in src
    assert 'KLP_RELOC_SYMBOL' in src

    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "_init(void);" not in header
    assert "_init(void) { return 0; }" in header
    assert "_cleanup(void);" not in header
    assert "_cleanup(void) {}" in header
    assert "IS_ENABLED" not in header


def test_templ_ibt_without_externalized_vars():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "6.0u2"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": False,
        "archs" : utils.ARCHS,
        "cve": None,
        "conf": "CONFIG_IPV6",
        "module" : "vmlinux",
        "file_funcs" : [["net/ipv6/rpl.c", "ipv6_rpl_srh_size"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[])

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # For this file and symbol, no externalized symbols are used, so
    # klp_funcs shouldn't be preset.
    # the include of livepatch.h should not be present because there are no externalized variables
    content = get_file_content(lp, cs)
    for check in ["LP_MODULE", "module_notify", "linux/module.h", "klp_funcs", "linux/livepatch.h>"]:
        assert check not in content

    # As the config only targets one arch, IS_ENABLED should be set
    assert "#if IS_ENABLED" not in content

    # Without CVE speficied, we should have XXXX-XXXX
    assert "CVE-XXXX-XXXX" in content

    # Without external symbols we don't need to implement the _init/_exit functions
    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "_init(void);" not in header
    assert "_init(void) { return 0; }" in header
    assert "_cleanup(void);" not in header
    assert "_cleanup(void) {}" in header
    assert "IS_ENABLED" not in header


def test_templ_kbuild_has_contents():
    """
    Making sure that Kbuild.inc has the correct content
    """
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "6.0u2"

    setup_args = {
        "lp_name" : lp,
        "lp_filter": cs,
        "no_check": True,
        "archs" : utils.ARCHS,
        "cve": None,
        "conf": "CONFIG_NVME_TCP",
        "module" : "nvme-tcp",
        "file_funcs" : [["drivers/nvme/host/tcp.c", "nvme_tcp_io_work"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : []
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, apply_patches=False, avoid_ext=[])

    kbuild_data = get_file_content(lp, cs, "Kbuild.inc")
    assert "CFLAGS_livepatch_bsc_test_templ_kbuild_has_contents.o += -Werror" in kbuild_data
    assert "CFLAGS_bsc_test_templ_kbuild_has_contents/livepatch_bsc_test_templ_kbuild_has_contents.o += -Werror" \
        in kbuild_data
