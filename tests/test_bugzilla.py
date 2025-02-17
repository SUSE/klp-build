# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from klpbuild.klplib.bugzilla import get_bug_title


def test_get_bug_title():
    assert get_bug_title("1227320") == "wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes"
