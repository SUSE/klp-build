# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza

from klpbuild.plugins.scan import scan


# This CVE is already covered on all codestreams
def test_scan_all_cs_patched(caplog):
    scan("2022-48801", "", "", False)

    assert "All supported codestreams are already patched" in caplog.text


def test_scan_with_extra_patches(caplog):
    extra_patch = "patches.suse/net-fix-__dst_negative_advice-race.patch"
    patches, _, _, _ = scan("2022-48801", "", "", False,
                            extra_patches=[extra_patch])

    # The additional patch should be included in the patch lists for
    # branches where it exists
    assert extra_patch in patches["15.5"]
