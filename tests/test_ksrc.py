# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

from klpbuild.klplib.ksrc import get_commit_files, ksrc_is_module_supported

def test_get_commit_files():
    expected = ["include/net/dst_ops.h",
                "include/net/sock.h",
                "net/ipv6/route.c",
                "net/xfrm/xfrm_policy.c"]
    commit = "604ed28f2720b3354a2eceb530c7e923566f70b8"
    files = get_commit_files(commit, inside_patch=True)
    assert len(set(files) & set(expected)) == len(expected)


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
