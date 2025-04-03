# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

from klpbuild.klplib.ksrc import get_commit_files

def test_get_commit_files():
    expected = ["include/net/dst_ops.h",
                "include/net/sock.h",
                "net/ipv6/route.c",
                "net/xfrm/xfrm_policy.c"]
    commit = "604ed28f2720b3354a2eceb530c7e923566f70b8"
    files = get_commit_files(commit, inside_patch=True)
    assert len(set(files) & set(expected)) == len(expected)
