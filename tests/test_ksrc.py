# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from klpbuild.klplib.ksrc import GitHelper

def test_multiline_upstream_commit_subject():
    _, subj = GitHelper.get_commit_data("49c47cc21b5b")
    assert subj == "net: tls: fix possible race condition between do_tls_getsockopt_conf() and do_tls_setsockopt_conf()"

