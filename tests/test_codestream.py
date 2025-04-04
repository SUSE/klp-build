# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela

import pytest

from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib.utils import ARCHS


def test_wrong_cs_filter():
    with pytest.raises(ValueError, match=r"Filter regexp error!"):
        Codestream.from_cs("wrong-filter")


def test_find_obj_path_arch():
    """
    Ensure the returned obj path doesn't contain any architecture info
    """
    cs = Codestream.from_data({
        "sle": 15,
        "sp": 5,
        "update": 15,
        "rt": "",
        "project": "SUSE:Maintenance:34200",
        "patchid": "",
        "kernel": "5.14.21-150500.55.68",
        "archs": [
            "x86_64",
            "s390x",
            "ppc64le"
        ],
        "files": {
            "net/sched/sch_taprio.c": {
                "module": "sch_taprio",
                "conf": "CONFIG_NET_SCH_TAPRIO",
                "symbols": [
                        "taprio_change"
                ],
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
                }
            }
        },
        "modules": {
            "sch_taprio": "lib/modules/5.14.21-150500.55.68-default/kernel/net/sched/sch_taprio.ko"
        },
        "repo": "SUSE_SLE-15-SP5_Update",
        "configs": {
            "CONFIG_NET_SCH_TAPRIO": {"x86_64":"m","ppc64le":"m","s390x":"m"}
            }
    })

    for arch in ARCHS:
        assert arch not in str(cs.find_obj_path(arch, "sch_taprio"))
