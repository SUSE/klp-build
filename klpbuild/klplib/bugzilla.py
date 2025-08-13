# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Authors: Fernando Gonzalez
#          Marcos Paulo de Souza <mpdesouza@suse.com>

import bugzilla
import time
from functools import wraps

from klpbuild.klplib.config import get_user_settings

__bzapi = None
def __check_is_connected(func):
    """
    This decorator checks whether there's an active connection to a bugzilla
    instance. If not, it will attempt to connect to the specified server.

    Args:
        func (function): The function to be wrapped.

    Returns:
        function: The wrapped function.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        global __bzapi
        if not __bzapi:
            __bzapi = __connect_to_bugzilla()
        return func(*args, **kwargs)
    return wrapper


def __connect_to_bugzilla():
    bz_key = get_user_settings("bugzilla_api_key", True)
    if 'changeit' in bz_key:
        raise RuntimeError("Change the bugzilla_api_key to a valid key.")

    return bugzilla.Bugzilla("https://bugzilla.suse.com", api_key=bz_key)


@__check_is_connected
def get_pending_bugs():
    """
    Return the lists of pending bugs and corresponding parent bugs (aka dependencies).
    "Pending bugs" are those tickets that are "open" and assigned to "kernel-lp" user.
    """
    query = __bzapi.build_query(
            status=["NEW","REOPENED","IN_PROGRESS"],
            component="Kernel Live Patches",
            assigned_to="kernel-lp")

    query["ids_only"] = True
    ids = [b.id for b in __bzapi.query(query)]
    bugs = __bzapi.getbugs(ids)

    deps_ids = [b.depends_on[0] for b in bugs if len(b.depends_on) > 0]
    deps_fields = ["status", "resolution", "assigned_to", "whiteboard"]
    deps = {d.id:d for d in __bzapi.getbugs(deps_ids,include_fields=deps_fields)}

    return bugs, deps


@__check_is_connected
def get_bug(bsc):
    """
    Fetch a bug's data indicated by the given bug id.

    Args:
        bsc (str/int): bug id. Must be a numerical value.

    Returns:
        bug object.
    """
    if isinstance(bsc, str) and not bsc.isnumeric():
        return None

    return __bzapi.getbug(bsc)


def get_bug_classification(bug):
    """
    Return the difficulty score assigned by Nicolai in the comment section.
    """
    rating = ["trivial", "medium", "complex"]
    comments = []
    i = 0

    while i < 5:
        try:
            comments = bug.getcomments()
            break
        except:
           # There's a max number of allowed simultaneous requests...
            time.sleep(5)
            i += 1

    for c in comments:
        if "nstange" in c["creator"]:
            return w if any((w:=i) in c["text"] for i in rating) else "unknown"

    return "None"


def get_bug_dep(bug, deps=None):
    """
    Return the corresponding dependency to the given bug.
    To speed up the lookup it allows passing a precalculated
    list will all the dependencies for all bugs, instead
    of fetching them from bugzilla one by one.
    """

    # XXX: Support returning more than one dependency?

    d = bug.depends_on
    if not d:
        return None

    if deps:
        return deps[d[0]]

    return get_bug(d[0])


def get_bug_cvss(bug):
    if bug is None:
        return "None"

    raw = bug.whiteboard.split(':')
    return raw[3] if len(raw) >= 4 else "None"


def get_bug_summary(bug):
    return bug.summary.split(':')


def get_bug_cve(bug):
    summary = get_bug_summary(bug)
    if len(summary) < 2:
        return ""

    return summary[1][5:].strip()


def get_bug_subsys(bug):
    summary = get_bug_summary(bug)
    if len(summary) < 3:
        return "Unknown"

    return summary[3][:40].strip()


def get_bug_prio(bug):
    return bug.priority[5:]


def is_bug_dropped(bug):
    return bug.resolution and bug.resolution in {"INVALID", "WONTFIX", "DUPLICATED"}


def get_bug_data(bug, dep):
    return (get_bug_cve(bug), get_bug_subsys(bug), get_bug_cvss(dep),
            get_bug_classification(dep), get_bug_prio(bug))


def get_bug_title(bug):
    """
    The bug description usually is after the "kernel live patch" message. Return
    a fixed message if the bug is not valid.
    """

    if not bug:
        return "Change me!"

    data = str(bug.summary)
    return data.split("kernel live patch: ")[1].strip()
