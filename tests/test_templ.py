# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect

import pytest

import klpbuild.klplib.templ as templ_module
from klpbuild.klplib import utils
from klpbuild.klplib.templ import get_multi_funcs
from klpbuild.plugins.extract import extract
from klpbuild.plugins.setup import run as setup
from tests.utils import FakeCS, get_codestreams_file, get_file_content

_generate_klpp_header = templ_module.__dict__["__generate_klpp_header"]


def test_templ_with_externalized_vars():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u25"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": utils.ARCHS,
        "conf": "CONFIG_PROC_FS",
        "module": "vmlinux",
        "file_funcs": [["fs/proc/cmdline.c", "cmdline_proc_show"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # As the code is using the default archs, which is all of them, the
    # IS_ENABLED macro shouldn't exist
    # the include of livepatch.h should not be present because 15.5 doesn't use IBT
    content = get_file_content(lp, cs)
    for check in [
        "LP_MODULE",
        "module_notify",
        "linux/module.h",
        "#if IS_ENABLED",
        "linux/livepatch.h",
    ]:
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
    cs = "15.5u25"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": {utils.ARCH},
        "conf": "CONFIG_IPV6",
        "module": "vmlinux",
        "file_funcs": [["net/ipv6/rpl.c", "ipv6_rpl_srh_size"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # For this file and symbol, no externalized symbols are used, so
    # klp_funcs shouldn't be preset.
    # the include of livepatch.h should not be present because 15.5 doesn't use IBT
    content = get_file_content(lp, cs)
    for check in [
        "LP_MODULE",
        "module_notify",
        "linux/module.h",
        "klp_funcs",
        "linux/livepatch.h>",
    ]:
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


# Check that IS_ENABLED macro is set only when the affected architectures of a
# CVE is not all architectures supported by the given codestream.
def test_is_enabled_only_on_cs_arcs():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "6.0u5"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": utils.ARCHS,
        "conf": "CONFIG_IPV6",
        "module": "vmlinux",
        "file_funcs": [
            ["net/ipv6/ip6_fib.c", "fib6_del_route", "fib6_add_rt2node"],
            ["net/ipv6/route.c", "rt6_nlmsg_size"],
        ],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    with pytest.raises(SystemExit):
        extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    for src in [
        "bsc_test_is_enabled_only_on_cs_arcs_net_ipv6_ip6_fib.c",
        "bsc_test_is_enabled_only_on_cs_arcs_net_ipv6_route.c",
    ]:
        content = get_file_content(lp, cs, src)
        # The given CVE affects all archs in all codestreams, meaning that IS_ENABLED
        # should not be set.
        assert "#if IS_ENABLED" not in content


# Check if only x86_64 is affected by the CVE, meaning that IS_ENABLED should be
# set in the final code
def test_is_enabled_only_on_x86():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.7u5"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": utils.ARCHS,
        "conf": "CONFIG_ACPI",
        "module": None,
        "file_funcs": [
            ["drivers/acpi/acpica/utcopy.c", "acpi_ut_copy_ipackage_to_ipackage"]
        ],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    content = get_file_content(lp, cs, f"livepatch_{lp}.c")
    # This CVE impact only x86, so IS_ENABLED should be present
    assert "#if IS_ENABLED" in content


# For multifile patches, a third file will be generated and called
# livepatch_XXX, and alongside this file the other files will have the prefix
# bscXXXXXXX.
def test_check_header_file_included():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.5u25"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": utils.ARCHS,
        "conf": "CONFIG_IPV6",
        "module": "vmlinux",
        "file_funcs": [
            ["net/ipv6/rpl.c", "ipv6_rpl_srh_size"],
            ["fs/proc/cmdline.c", "cmdline_proc_show"],
        ],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    # Check that for file fs/proc/cmdline.c there are externalized symbols, so
    # the prototype of init/cleanup are created on header
    # As net/ipv6/rpl.c there are no externalized symbols we expect that it's
    # prototype isn't created on livepatch_header file
    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "fs_proc_cmdline_init(void)" in header
    assert "fs_proc_cmdline_cleanup(void)" in header
    assert "net_ipv6_rpl" not in header


def test_templ_cve_specified():
    lp = "bsc1227320"
    cs = "15.5u30"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": False,
        "archs": {utils.ARCH},
        "conf": "CONFIG_PROC_FS",
        "module": "vmlinux",
        "file_funcs": [["fs/proc/cmdline.c", "cmdline_proc_show"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    # The CVE is found by using the bsc number
    assert "2024-35789" == get_codestreams_file(lp)["cve"]


def test_templ_exts_mod_name():
    """
    This extraction should add a new external symbol from module nvme-tcp, but the kallsyms relocation
    need the module to be nvme_tcp.
    """
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.4u45"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": utils.ARCHS,
        "conf": "CONFIG_NVME_TCP",
        "module": "nvme-tcp",
        "file_funcs": [["drivers/nvme/host/tcp.c", "nvme_tcp_io_work"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    # The module name should be nvme_tcp instead of nvme-tcp
    assert (
        '{ "nvme_tcp_try_send", (void *)&klpe_nvme_tcp_try_send, "nvme_tcp" },'
        in get_file_content(lp, cs)
    )

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
    cs = "6.0u11"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": utils.ARCHS,
        "conf": "CONFIG_NVME_TCP",
        "module": "nvme-tcp",
        "file_funcs": [["drivers/nvme/host/tcp.c", "nvme_tcp_io_work"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    src = get_file_content(lp, cs)
    # Requires the include since it's a codestream that uses IBT and has externalized symbols
    assert "include <linux/livepatch.h>" in src
    assert "KLP_RELOC_SYMBOL" in src

    header = get_file_content(lp, cs, f"livepatch_{lp}.h")
    assert "_init(void);" not in header
    assert "_init(void) { return 0; }" in header
    assert "_cleanup(void);" not in header
    assert "_cleanup(void) {}" in header
    assert "IS_ENABLED" not in header


def test_templ_ibt_without_externalized_vars():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "6.0u11"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": {utils.ARCH},
        "conf": "CONFIG_IPV6",
        "module": "vmlinux",
        "file_funcs": [["net/ipv6/rpl.c", "ipv6_rpl_addr_compress"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # For this file and symbol, no externalized symbols are used, so
    # klp_funcs shouldn't be preset.
    # the include of livepatch.h should not be present because there are no externalized variables
    content = get_file_content(lp, cs)
    for check in [
        "LP_MODULE",
        "module_notify",
        "linux/module.h",
        "klp_funcs",
        "linux/livepatch.h>",
    ]:
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


def test_templ_kbuild_has_contents():
    """
    Making sure that Kbuild.inc has the correct content
    """
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "6.0u11"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": utils.ARCHS,
        "conf": "CONFIG_NVME_TCP",
        "module": "nvme-tcp",
        "file_funcs": [["drivers/nvme/host/tcp.c", "nvme_tcp_io_work"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    kbuild_data = get_file_content(lp, cs, "Kbuild.inc")
    assert (
        "CFLAGS_livepatch_bsc_test_templ_kbuild_has_contents.o += -Werror"
        in kbuild_data
    )
    assert (
        "CFLAGS_bsc_test_templ_kbuild_has_contents/livepatch_bsc_test_templ_kbuild_has_contents.o += -Werror"
        in kbuild_data
    )


# ── get_multi_funcs ──────────────────────────────────────────────────────────


def test_get_multi_funcs_ibt_returns_empty():
    """IBT codestreams don't need the multi-entry wiring file."""
    assert get_multi_funcs(FakeCS({}, ibt=True), "bsc123") == ("", "")


def test_get_multi_funcs_no_ext_symbols():
    """Files without ext_symbols are skipped; only the initial ret line remains."""
    inits, cleanups = get_multi_funcs(
        FakeCS({"fs/proc/cmdline.c": {"ext_symbols": {}}}), "bsc123"
    )

    assert "\tint ret;\n" in inits
    assert cleanups == ""


def test_get_multi_funcs_vmlinux_file():
    """A file whose symbols live in vmlinux: _init added, no _cleanup."""
    inits, cleanups = get_multi_funcs(
        FakeCS({"fs/proc/cmdline.c": {"ext_symbols": {"seq_printf": "vmlinux"}}}),
        "bsc123",
    )

    assert "bsc123_fs_proc_cmdline_init()" in inits
    assert "cleanup" not in cleanups


def test_get_multi_funcs_module_file():
    """A file whose symbols come from a module: both _init and _cleanup added."""
    inits, cleanups = get_multi_funcs(
        FakeCS(
            {
                "drivers/nvme/host/tcp.c": {
                    "ext_symbols": {"nvme_tcp_try_send": "nvme_tcp"}
                }
            },
            mods={"drivers/nvme/host/tcp.c": "nvme_tcp"},
        ),
        "bsc123",
    )

    assert "bsc123_drivers_nvme_host_tcp_init()" in inits
    assert "bsc123_drivers_nvme_host_tcp_cleanup()" in cleanups


def test_get_multi_funcs_multiple_files():
    """Mix of vmlinux and module files: inits for both, cleanup only for module."""
    inits, cleanups = get_multi_funcs(
        FakeCS(
            {
                "fs/proc/cmdline.c": {"ext_symbols": {"seq_printf": "vmlinux"}},
                "drivers/nvme/host/tcp.c": {
                    "ext_symbols": {"nvme_tcp_try_send": "nvme_tcp"}
                },
            },
            mods={"drivers/nvme/host/tcp.c": "nvme_tcp"},
        ),
        "bsc123",
    )

    assert "bsc123_fs_proc_cmdline_init()" in inits
    assert "bsc123_drivers_nvme_host_tcp_init()" in inits
    assert "cmdline_cleanup" not in cleanups
    assert "bsc123_drivers_nvme_host_tcp_cleanup()" in cleanups


def test_get_multi_funcs_skips_file_without_ext_symbols():
    """A file with no ext_symbols is ignored even when another file has them."""
    inits, cleanups = get_multi_funcs(
        FakeCS(
            {
                "fs/proc/cmdline.c": {"ext_symbols": {"seq_printf": "vmlinux"}},
                "net/ipv6/rpl.c": {"ext_symbols": {}},
            }
        ),
        "bsc123",
    )

    assert "bsc123_fs_proc_cmdline_init()" in inits
    assert "net_ipv6_rpl" not in inits
    assert "net_ipv6_rpl" not in cleanups


def test_get_multi_funcs_hyphen_in_lp_name():
    """Hyphens in lp_name are converted to underscores in the generated symbol names."""
    inits, _ = get_multi_funcs(
        FakeCS({"fs/proc/cmdline.c": {"ext_symbols": {"seq_printf": "vmlinux"}}}),
        "bsc-1234",
    )

    # lp_out_file keeps the hyphen; get_fname converts it to _
    assert "bsc_1234_fs_proc_cmdline_init()" in inits


# ── __generate_klpp_header ───────────────────────────────────────────────────


def test_generate_klpp_header_empty_files():
    """No source files → empty string."""
    assert _generate_klpp_header(FakeCS({})) == ""


def test_generate_klpp_header_no_structs():
    """Protos without struct parameters → sorted function declarations only."""
    result = _generate_klpp_header(
        FakeCS(
            {
                "foo.c": {
                    "klpp_symbols": {
                        "baz": "void klpp_baz(int x);",
                        "bar": "int klpp_bar(void);",
                    }
                }
            }
        )
    )

    assert "int klpp_bar(void);" in result
    assert "void klpp_baz(int x);" in result
    assert result.index("klpp_bar") < result.index("klpp_baz")
    assert "struct" not in result


def test_generate_klpp_header_with_structs():
    """Proto with a struct parameter → forward declaration prepended."""
    result = _generate_klpp_header(
        FakeCS(
            {
                "foo.c": {
                    "klpp_symbols": {
                        "bar": "int klpp_bar(struct sk_buff *skb);",
                    }
                }
            }
        )
    )

    assert "struct sk_buff;" in result
    assert "int klpp_bar(struct sk_buff *skb);" in result
    assert result.index("struct sk_buff;") < result.index("int klpp_bar")


def test_generate_klpp_header_dedup_structs():
    """The same struct appearing in multiple protos is declared only once."""
    result = _generate_klpp_header(
        FakeCS(
            {
                "foo.c": {
                    "klpp_symbols": {"foo": "int klpp_foo(struct sk_buff *skb);"}
                },
                "bar.c": {
                    "klpp_symbols": {"bar": "int klpp_bar(struct sk_buff *pkt);"}
                },
            }
        )
    )

    assert result.count("struct sk_buff;") == 1


def test_generate_klpp_header_multiple_structs_sorted():
    """Multiple distinct structs are forward-declared in alphabetical order."""
    result = _generate_klpp_header(
        FakeCS(
            {
                "foo.c": {
                    "klpp_symbols": {
                        "foo": "int klpp_foo(struct zebra *z, struct alpha *a);",
                    }
                }
            }
        )
    )

    assert "struct alpha;" in result
    assert "struct zebra;" in result
    assert result.index("struct alpha;") < result.index("struct zebra;")


def test_generate_klpp_header_empty_klpp_symbols_in_file():
    """A file with an empty klpp_symbols dict contributes nothing."""
    result = _generate_klpp_header(
        FakeCS(
            {
                "foo.c": {"klpp_symbols": {}},
                "bar.c": {"klpp_symbols": {"baz": "void klpp_baz(void);"}},
            }
        )
    )

    assert result == "void klpp_baz(void);"


def test_generate_klpp_header_struct_in_return_type():
    """A struct in the return type also triggers a forward declaration."""
    result = _generate_klpp_header(
        FakeCS(
            {
                "foo.c": {
                    "klpp_symbols": {
                        "bar": "struct sk_buff *klpp_bar(void);",
                    }
                }
            }
        )
    )

    assert "struct sk_buff;" in result
    assert result.index("struct sk_buff;") < result.index("struct sk_buff *klpp_bar")


def test_generate_klpp_header_funcs_sorted_across_files():
    """Prototypes from multiple files are sorted together, not per-file."""
    result = _generate_klpp_header(
        FakeCS(
            {
                "foo.c": {"klpp_symbols": {"zoo": "void klpp_zoo(void);"}},
                "bar.c": {"klpp_symbols": {"alpha": "int klpp_alpha(void);"}},
            }
        )
    )

    assert result.index("klpp_alpha") < result.index("klpp_zoo")
