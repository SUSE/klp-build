# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

from klpbuild.klplib.ksrc import (get_patches, get_patches_files,
                                  ksrc_is_module_supported,
                                  get_branch_patches, get_patch_subject)

def test_get_patches_files():
    patch = ["patches.suse/net-fix-__dst_negative_advice-race.patch"]
    expected = {'include/net/dst_ops.h': '',
                'include/net/sock.h': '__dst_negative_advice',
                'net/ipv4/route.c': 'ipv4_negative_advice',
                'net/ipv6/route.c': 'ip6_negative_advice',
                'net/xfrm/xfrm_policy.c': 'xfrm_negative_advice'}

    files = get_patches_files(patch, "SLE15-SP6-LTSS")
    assert set(files.keys()) == set(expected.keys())
    for f, diffs in files.items():
        assert len(diffs[0]) and expected[f] in diffs[0]

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
    supported, _ = ksrc_is_module_supported(mod, "6.4.0-20")
    assert not supported
    # Expected: "- drivers/net/wireless/*"
    supported, _ = ksrc_is_module_supported(mod, "4.12.14-122.255")
    assert not supported

    mod = "drivers/net/wireless/intersil/prism54/prism54"
    # Expected: "-! drivers/net/wireless/intersil/prism54/prism54"
    supported, _ = ksrc_is_module_supported(mod, "5.14.21-150400.24.144")
    assert not supported

    mod = "drivers/net/wireless/mac80211_hwsim"
    # Expected: "  drivers/net/wireless/mac80211_hwsim"
    supported, filtered = ksrc_is_module_supported(mod, "5.14.21-150400.24.144")
    assert supported and not filtered

    mod = "net/tipc/tipc"
    # Expected: "+external	net/tipc/tipc"
    supported, _ = ksrc_is_module_supported(mod, "6.4.0-150600.23.65")
    assert not supported

    mod = "net/netfilter/ipset/ip_set_bitmap_ip"
    # Expected: "+base	net/netfilter/ipset/ip_set_bitmap_ip    # ipset: IP bitmap"
    supported, filtered = ksrc_is_module_supported(mod, "6.4.0-10")
    assert supported and not filtered

    mod = "fs/gfs2/gfs2"
    # Expected: "+fs/gfs2/gfs2-kmp"
    supported, filtered = ksrc_is_module_supported(mod, "6.12.0-160000.5")
    assert supported and filtered


def test_get_rt_patches():
    expected = [
            "patches.suse/bpf-Check-bloom-filter-map-value-size.patch",
            "patches.suse/bpf-Protect-against-int-overflow-for-stack-access-si.patch"
            ]
    patches = get_branch_patches("2024-35905", "SUSE-2024-RT")
    assert patches and expected == patches


def test_get_patches_with_extra_patches():
    extra_patch = "patches.suse/net-fix-__dst_negative_advice-race.patch"
    cve = "2022-48801"

    _, patches = get_patches(cve, extra_patches=[extra_patch])

    # The additional patch should appear before the CVE patch on branches
    # where it exists
    sp5_patches = patches["15.5"]
    assert extra_patch in sp5_patches
    assert sp5_patches.index(extra_patch) == 0


def test_get_patches_with_nonexistent_extra_patches():
    cve = "2022-48801"

    _, patches_without = get_patches(cve)
    _, patches_with = get_patches(cve, extra_patches=["patches.suse/does-not-exist.patch"])

    # Non-existent additional patches should be silently skipped, so the
    # patch lists must be identical
    for bc in patches_without:
        assert patches_without[bc] == patches_with[bc]
