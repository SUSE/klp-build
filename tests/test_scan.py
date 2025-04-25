# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza

import pytest
import re

from klpbuild.plugins.scan import scan

# This CVE is already covered on all codestreams
def test_scan_all_cs_patched(caplog):
    with pytest.raises(SystemExit):
        scan("2022-48801", "", False, "", False)

    assert "All supported codestreams are already patched" in caplog.text

def test_scan_update_ref_commits(caplog):
    '''
    The CVE has several related commits updating the patch's "Reference".
    The commits' message might lead to false-positives:
    ```
    Update
    patches.suse/s390-vfio-ap-always-filter-entire-AP-matrix.patch
    (git-fixes bsc#1218988 CVE-2024-26620 bsc#1221298).
     ```
    klp-build should be able to detect these false-positives and discard them.
    '''
    with pytest.raises(SystemExit):
        scan("2024-26620", "", False, "", False)

    assert "All supported codestreams are already patched" in caplog.text
    assert "b046ad18ee8d6e0df682b28c0dc45056554c5fda" not in caplog.text
    assert "4fb9779c0bb7188d837df9e43e6f84d067d0efd4" not in caplog.text

def test_scan_duplicate_commits(caplog):
    '''
    The CVE has two identical commits intrudicing the same patch for the
    same SLE (15.3). klp-build should discard the newest commit and keep
    the oldest one.
    '''
    with pytest.raises(SystemExit):
        scan("2021-47511", "", False, "", False)

    # Newest (only appears in the cve-5.3 branch)
    assert "094796a2bf2698dc8604dc319736ed207fd09c93" not in caplog.text
    # Oldest
    assert "69603451953a96fe87621abc34b771c41be859be" in caplog.text

def test_scan_merge_commits(caplog):
    '''
    The CVE has a related merge commit. klp-build should skip it
    and only show the commits introducing the patches.
    '''
    scan("2024-35905", "", False, "", False)

    assert "6959d874bc4db32ad6baa18779a145204576b5b8" not in caplog.text
    rt= ("6.0rt: SUSE-2024-RT\n.*"
        "72c76c85224ee4c8e51c77d6c407401f6935508d\n.*"
        "5fa3c1186f44343ae6130db7f10c5284da78b461\n")
    assert re.search(rt, caplog.text)
