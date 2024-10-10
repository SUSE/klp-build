# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from klpbuild.codestream import Codestream
from klpbuild.config import Config
from tests.utils import get_file_content, get_workdir



def test_filter():
    lp = "bsc9999999"

    def to_cs(cs_list):
        ret = []

        for cs in cs_list:
            ret.append(Codestream.from_cs("", cs))

        return ret


    # Same output because filter and skip were not informed
    assert Config(lp, "").filter_cs(to_cs(["12.5u10", "15.6u10"])) == to_cs(["12.5u10", "15.6u10"])

    # Filter only one codestream
    assert Config(lp, "12.5u10").filter_cs(to_cs(["12.5u10", "12.5u11", "15.6u10"])) == \
                                                    to_cs(["12.5u10"])

    # Filter codestreams using regex
    assert Config(lp, "12.5u1[01]").filter_cs(to_cs(["12.5u10", "12.5u11", "15.6u10"])) \
                                            == to_cs(["12.5u10", "12.5u11"])

    assert Config(lp, "12.5u1[01]|15.6u10").filter_cs(to_cs(["12.5u10",
                                                             "12.5u11",
                                                             "15.6u10"])) \
                                            == to_cs(["12.5u10", "12.5u11", "15.6u10"])

    # Use skip with filter
    assert Config(lp, "12.5u1[01]", skips="15.6u10").filter_cs(to_cs(["12.5u10",
                                                                      "12.5u11",
                                                                      "15.6u10"])) \
                                            == to_cs(["12.5u10", "12.5u11"])

    # Use skip with filter
    assert Config(lp, "12.5u1[01]", skips="15.6").filter_cs(to_cs(["12.5u10",
                                                                   "12.5u11",
                                                                   "15.6u12",
                                                                   "15.6u13"])) \
                                            == to_cs(["12.5u10", "12.5u11"])

    # filter is off, but skip will also only filter the 12.5 ones
    assert Config(lp, "", skips="15.6").filter_cs(to_cs(["12.5u10", "12.5u11",
                                                         "15.6u12", "15.6u13"])) \
                                            == to_cs(["12.5u10", "12.5u11"])

    assert Config(lp, "", skips="15.6u13").filter_cs(to_cs(["12.5u10",
                                                            "12.5u11",
                                                            "15.6u12",
                                                            "15.6u13"])) \
                                            == to_cs(["12.5u10", "12.5u11", "15.6u12"])
