import klpbuild.utils as utils
from klpbuild.codestream import Codestream

def test_group_classify():
    assert utils.classify_codestreams(["15.2u10", "15.2u11", "15.3u10", "15.3u12"]) == \
                                        ["15.2u10-11", "15.3u10-12"]

    assert utils.classify_codestreams([Codestream("", "", 15, 2, 10, False),
                                        Codestream("", "", 15, 2, 11, False),
                                        Codestream("", "", 15, 3, 10, False),
                                        Codestream("", "", 15, 3, 12, False)]) == \
                                        ["15.2u10-11", "15.3u10-12"]
