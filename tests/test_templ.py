# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from klpbuild.extractor import Extractor
from klpbuild.setup import Setup
import klpbuild.utils as utils
from tests.utils import get_file_content

def test_templ_with_externalized_vars():
    lp = "bsc9999999"
    cs = "15.5u19"

    Setup(lp_name=lp, lp_filter=cs, data_dir=None, cve=None,
          file_funcs=[["fs/proc/cmdline.c", "cmdline_proc_show"]],
          mod_file_funcs=[], conf_mod_file_funcs=[], mod_arg="vmlinux",
          conf="CONFIG_PROC_FS",
          archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, app="ce",
                     avoid_ext=[], ignore_errors=False).run()

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
    lp = "bsc9999999"
    cs = "15.5u19"

    Setup(lp_name=lp, lp_filter=cs, data_dir=None, cve=None,
          file_funcs=[["net/ipv6/rpl.c", "ipv6_rpl_srh_size"]],
          mod_file_funcs=[], conf_mod_file_funcs=[], mod_arg="vmlinux",
          conf="CONFIG_IPV6",
          archs=[utils.ARCH], skips=None, no_check=False).setup_project_files()

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, app="ce",
                     avoid_ext=[], ignore_errors=False).run()

    # As we passed vmlinux as module, we don't have the module notifier and
    # LP_MODULE, linux/module.h is not included
    # For this file and symbol, no externalized symbols are used, so
    # klp_funcs shouldn't be preset.
    content = get_file_content(lp, cs)
    for check in ["LP_MODULE", "module_notify", "linux/module.h", "klp_funcs"]:
        assert check not in content

    # As the config only targets x86_64, IS_ENABLED should be set
    assert "#if IS_ENABLED" in content


# For multifile patches, a third file will be generated and called
# livepatch_XXX, and alongside this file the other files will have the prefix
# bscXXXXXXX.
def test_check_header_file_included():
    lp = "bsc9999999"
    cs = "15.5u17"

    Setup(lp_name=lp, lp_filter=cs, data_dir=None, cve=None,
          file_funcs=[["net/ipv6/rpl.c", "ipv6_rpl_srh_size"], ["kernel/events/core.c", "perf_event_exec"]],
          mod_file_funcs=[], conf_mod_file_funcs=[], mod_arg="vmlinux",
          conf="CONFIG_IPV6",
          archs=[utils.ARCH], skips=None, no_check=False).setup_project_files()

    Extractor(lp_name=lp, lp_filter=cs, apply_patches=False, app="ce",
                     avoid_ext=[], ignore_errors=False).run()

    # test the livepatch_ prefix file
    assert "Upstream commit:" in get_file_content(lp, cs)

    # Check the other two files
    assert "Upstream commit:" not in get_file_content(lp, cs, f"{lp}_kernel_events_core.c")
    assert "Upstream commit:" not in get_file_content(lp, cs, f"{lp}_net_ipv6_rpl.c")
