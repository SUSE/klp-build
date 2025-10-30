# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

from klpbuild.klplib.ksrc import (get_patches_files, ksrc_is_module_supported,
                                  get_branch_patches, get_patch_subject)

def test_get_patches_files():
    patch = ["patches.suse/net-fix-__dst_negative_advice-race.patch"]
    expected = {'include/net/dst_ops.h': [],
                'include/net/sock.h': ['__dst_negative_advice'],
                'net/ipv4/route.c': ['ipv4_negative_advice'],
                'net/ipv6/route.c': ['ip6_negative_advice'],
                'net/xfrm/xfrm_policy.c': ['xfrm_negative_advice']}

    files = get_patches_files(patch, "SLE15-SP6")
    assert len(files) == len(expected)
    for file, funcs in files.items():
        assert file in expected
        if expected[file]:
            assert set(expected[file]) & funcs


def test_get_patch_subject():
    expected = "tcp/dccp: Don't use timer_pending() in reqsk_queue_unlink()."
    patch = "patches.suse/tcp-dccp-Don-t-use-timer_pending-in-reqsk_queue_unlink.patch"
    assert expected == get_patch_subject(patch, "SLE15-SP7")

    expected = "mptcp: fix TCP options overflow."
    patch = "patches.suse/mptcp-fix-TCP-options-overflow.patch"
    assert expected == get_patch_subject(patch, "SLE15-SP7")


def test_is_module_supported():
    mod = "drivers/net/wireless/ath/ath12k/ath12k"
    # Expected: "- drivers/net/wireless/ath/ath12k/ath12k"
    assert not ksrc_is_module_supported(mod, "6.4.0-20")
    # Expected: "- drivers/net/wireless/*"
    assert not ksrc_is_module_supported(mod, "4.12.14-122.255")

    mod = "drivers/net/wireless/intersil/prism54/prism54"
    # Expected: "-! drivers/net/wireless/intersil/prism54/prism54"
    assert not ksrc_is_module_supported(mod, "5.14.21-150400.24.144")

    mod = "drivers/net/wireless/mac80211_hwsim"
    # Expected: "  drivers/net/wireless/mac80211_hwsim"
    assert ksrc_is_module_supported(mod, "5.14.21-150400.24.144")

    mod = "net/tipc/tipc"
    # Expected: "+external	net/tipc/tipc"
    assert not ksrc_is_module_supported(mod, "6.4.0-150600.23.65")

    mod = "net/netfilter/ipset/ip_set_bitmap_ip"
    # Expected: "+base	net/netfilter/ipset/ip_set_bitmap_ip    # ipset: IP bitmap"
    assert ksrc_is_module_supported(mod, "6.4.0-10")


def test_get_rt_patches():
    expected = [
            "patches.suse/bpf-Check-bloom-filter-map-value-size.patch",
            "patches.suse/bpf-Protect-against-int-overflow-for-stack-access-si.patch"
            ]
    patches = get_branch_patches("2024-35905", "SUSE-2024-RT")
    assert patches and expected == patches
