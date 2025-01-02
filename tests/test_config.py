# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from klpbuild.klplib.codestream import Codestream
from klpbuild.utils import filter_codestreams


def test_filter():
    def list_to_dict(cs_list):
        ret = {}

        for cs in cs_list:
            ret[cs] = Codestream.from_cs(cs)

        return ret

    def list_to_cs(cs_list):
        ret = []

        for cs in cs_list:
            ret.append(Codestream.from_cs(cs))

        return ret

    # Same output because filter and skip were not informed
    assert filter_codestreams("", "", list_to_dict(["12.5u10", "15.6u10"])) \
                            == list_to_cs(["12.5u10", "15.6u10"])


    # Same as before, but using a list instead of a dict
    assert filter_codestreams("", "", list_to_cs(["12.5u10", "15.6u10"])) \
                            == list_to_cs(["12.5u10", "15.6u10"])

    # Filter only one codestream
    assert filter_codestreams("12.5u10", "", list_to_dict(["12.5u10", "12.5u11", "15.6u10"])) == \
                                                    list_to_cs(["12.5u10"])

    # Filter codestreams using regex
    assert filter_codestreams("12.5u1[01]", "", list_to_dict(["12.5u10", "12.5u11", "15.6u10"])) \
                                            == list_to_cs(["12.5u10", "12.5u11"])

    assert filter_codestreams("12.5u1[01]|15.6u10", "", list_to_dict(["12.5u10", "12.5u11", "15.6u10"])) \
                                            == list_to_cs(["12.5u10", "12.5u11", "15.6u10"])

    # Use skip with filter
    assert filter_codestreams("12.5u1[01]", "15.6u10", list_to_dict(["12.5u10", "12.5u11", "15.6u10"])) \
                                            == list_to_cs(["12.5u10", "12.5u11"])

    # Use skip with filter
    assert filter_codestreams("12.5u1[01]", "15.6", list_to_dict(["12.5u10", "12.5u11", "15.6u12", "15.6u13"])) \
                                            == list_to_cs(["12.5u10", "12.5u11"])

    # filter is off, but skip will also only filter the 12.5 ones
    assert filter_codestreams("", "15.6", list_to_dict(["12.5u10", "12.5u11", "15.6u12", "15.6u13"])) \
                                            == list_to_cs(["12.5u10", "12.5u11"])

    assert filter_codestreams("", "15.6u13", list_to_dict(["12.5u10", "12.5u11", "15.6u12", "15.6u13"])) \
                                            == list_to_cs(["12.5u10", "12.5u11", "15.6u12"])
