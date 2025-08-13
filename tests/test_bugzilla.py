# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from klpbuild.klplib.bugzilla import get_bug, get_bug_title, get_pending_bugs, get_bug_data, get_bug_dep

def test_get_pending_bugs():
    bugs, deps = get_pending_bugs()
    assert len(bugs) > 0 and len(deps) > 0


def test_get_bug_title():
    bug = get_bug("1227320")
    assert bug and get_bug_title(bug) == "wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes"
    assert get_bug_title(get_bug("blah")) == "Change me!"


def test_get_bug_data():
    bug = get_bug("1227320")
    dep = get_bug_dep(bug)
    cve, subsys, cvss, level, prio = get_bug_data(bug, dep)
    assert (cve == "2024-35789" and subsys == "wifi"
            and cvss == "7.8" and level == "None"
            and prio == "Medium")
