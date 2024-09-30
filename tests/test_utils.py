import klpbuild.utils as utils

def test_group_classify():
    assert utils.classify_codestreams(["15.2u10", "15.2u11", "15.3u10", "15.3u12"]) == \
                                        ["15.2u10-11", "15.3u10-12"]
