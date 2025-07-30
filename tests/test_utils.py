from klpbuild.klplib import utils
from klpbuild.klplib.codestream import Codestream


def test_group_classify():
    assert utils.classify_codestreams(["15.2u10", "15.2u11", "15.3u10", "15.3u12"]) == \
                                        ["15.2u10-11", "15.3u10-12"]

    assert utils.classify_codestreams([Codestream("15.2u10"),
                                       Codestream("15.2u11"),
                                       Codestream("15.3u10"),
                                       Codestream("15.3u12")]) == \
        ["15.2u10-11", "15.3u10-12"]

    assert utils.classify_codestreams([Codestream("15.5u11"),
                                       Codestream("15.5u14"),
                                       Codestream("15.6u0"),
                                       Codestream("15.5u6"),
                                       Codestream("15.5u8"),
                                       Codestream("15.5u9"),
                                       Codestream("15.6u10"),
                                       Codestream("15.4u24"),
                                       Codestream("15.4u26")]) == \
        ["15.4u24-26", "15.5u6-9", "15.5u11-14", "15.6u0-10"]
