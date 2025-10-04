# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

from klpbuild.klplib.kernel_tree import get_commit_data, get_commit_body, find_commit

def test_multiline_upstream_commit_subject():
    _, subj, _ = get_commit_data("49c47cc21b5b")
    assert subj == "net: tls: fix possible race condition between do_tls_getsockopt_conf() and do_tls_setsockopt_conf()"


def test_find_commit():
    subj = "tcp/dccp: Don't use timer_pending() in reqsk_queue_unlink()."
    assert "af9aa67aec10" in find_commit(subj, "SLE15-SP7")

    subj = "ALSA: firewire-lib: Avoid division by zero in apply_constraint_to_size()"
    assert "76935334e479" in find_commit(subj, "SLE15-SP6")


def test_get_commit_body():
    file = "net/ipv4/inet_connection_sock.c"
    func = "return __inet_csk_reqsk_queue_drop(sk, req, false);"
    assert func in get_commit_body("af9aa67aec100", file)
