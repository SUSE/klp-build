# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from klpbuild.klplib.bugzilla import (get_bug, get_bug_title, get_pending_bugs,
                                      get_bug_data, get_bug_desc, get_bug_prio)


def test_get_pending_bugs():
    bugs = get_pending_bugs()
    assert len(bugs) > 0


def test_get_bug_title():
    bug = get_bug("1227320")
    assert bug and get_bug_title(bug) == "wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes"
    assert get_bug_title(get_bug("blah")) == "Change me!"


def test_get_bug_data():
    bug = get_bug("1227320")
    data = get_bug_data(bug)
    assert (data.cve == "2024-35789" and data.subsys == "wifi"
            and data.cvss == "7.8" and data.prio == "Medium")


def test_get_bug_desc():
    expected = "In the Linux kernel, the following vulnerability has been resolved:"
    bug = get_bug("1227320")
    desc = get_bug_desc(bug)
    assert desc and expected in desc


def test_get_bug_prio():
    expected = "Medium"
    bug = get_bug("1263002")
    prio = get_bug_prio(bug)
    assert (prio == expected and
            bug.priority[5:] == "Medium" and
            bug.severity == "Major")
