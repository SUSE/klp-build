# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela

import pytest

from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib.utils import ARCHS


def test_wrong_cs_name():
    with pytest.raises(ValueError, match=r"Name format error"):
        Codestream("wrong-filter")


def test_find_obj_path_arch():
    """
    Ensure the returned obj path doesn't contain any architecture info
    """
    cs = Codestream.from_data({
        "name": "15.5u15",
        "project": "SUSE:Maintenance:34200",
        "patchid": "",
        "kernel": "5.14.21-150500.55.68",
        "eol": "2025-11-09",
        "archs": [
            "x86_64",
            "s390x",
            "ppc64le"
        ],
        "files": {
            "net/sched/sch_taprio.c": {
                "module_name": "sch_taprio",
                "config_name": "CONFIG_NET_SCH_TAPRIO",
                "affected_symbols": [
                        "taprio_change"
                ],
                "ibt": False,
                "dup_symbols": [],
                "ext_symbols": {
                    "sch_taprio": [
                        "advance_sched",
                        "parse_taprio_schedule",
                        "taprio_dequeue_offload",
                        "taprio_dequeue_soft",
                        "taprio_free_sched_cb",
                        "taprio_get_time",
                        "taprio_offload_free",
                        "taprio_parse_clockid",
                        "taprio_peek_offload",
                        "taprio_peek_soft",
                        "taprio_policy",
                        "taprio_set_picos_per_byte"
                    ]
                },
                "klpp_symbols": {}
            }
        },
        "modules": {
            "sch_taprio": {
                "supported": True,
                "blacklisted": False,
                "obj_paths": {
                    # The bug this test guards against is find_obj_path
                    # returning a path that contains the arch name (because
                    # the cache used to be arch-blind). Cache the same
                    # arch-relative path under each arch key.
                    "x86_64":  "lib/modules/5.14.21-150500.55.68-default/kernel/net/sched/sch_taprio.ko",
                    "ppc64le": "lib/modules/5.14.21-150500.55.68-default/kernel/net/sched/sch_taprio.ko",
                    "s390x":   "lib/modules/5.14.21-150500.55.68-default/kernel/net/sched/sch_taprio.ko",
                }
            }
        },
        "repo": "SUSE_SLE-15-SP5_Update",
        "configs": {
            "CONFIG_NET_SCH_TAPRIO": {"x86_64":"m","ppc64le":"m","s390x":"m"}
            },
        "required_patches" : ""
    })

    for arch in ARCHS:
        assert arch not in str(cs.find_obj_path(arch, "sch_taprio"))


def test_sle16rt_config():
    cs = Codestream("16.0rtu0", kernel="6.12.0-160000.11")
    config_content = cs.get_config_content()
    assert "CONFIG_RCU_BOOST_DELAY" in config_content
