# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Authors: Fernando Gonzalez
#          Marcos Paulo de Souza <mpdesouza@suse.com>

import bugzilla
from klpbuild.klplib.config import get_user_settings


def get_bug_data(bsc):
    bz_key = get_user_settings("bugzilla_api_key", True)
    if 'changeit' in bz_key:
        raise RuntimeError("Change the bugzilla_api_key to a valid key.")

    bzapi = bugzilla.Bugzilla("https://bugzilla.suse.com", api_key=bz_key)

    return bzapi.getbug(bsc)


def get_bug_title(bsc):
    """
    The bug description usually is after the "kernel live patch" message. Return a fixes message
    if the livepatch name is not an ID from a bug on bugzilla.
    """
    if not bsc.isnumeric():
        return "Change me!"

    data = str(get_bug_data(int(bsc)).summary)
    return data.split("kernel live patch: ")[1].strip()
