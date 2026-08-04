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


def test_filter_fast():
    assert utils.filter_fast(
        [
            Codestream("6.0u0"),
            Codestream("15.2u10"),
            Codestream("15.2u11"),
            Codestream("15.3u10"),
            Codestream("15.3u12"),
        ]
    ) == [Codestream("6.0u0"), Codestream("15.2u10"), Codestream("15.3u10")]


def test_is_cve_valid():
    # Valid CVEs (years 2020-2029, 4 to 7 digit IDs)
    assert utils.is_cve_valid("2020-1234")
    assert utils.is_cve_valid("2025-98765")
    assert utils.is_cve_valid("2029-1234567")
    assert utils.is_cve_valid("2023-1234")

    # Wrong year (before 2020 or after 2029)
    assert not utils.is_cve_valid("2019-1234")
    assert not utils.is_cve_valid("2030-1234")
    assert not utils.is_cve_valid("1999-1234")

    # Too few digits in ID
    assert not utils.is_cve_valid("2022-123")

    # Too many digits in ID
    assert not utils.is_cve_valid("2022-12345678")

    # Wrong format
    assert not utils.is_cve_valid("CVE-2022-1234")
    assert not utils.is_cve_valid("2022_1234")
    assert not utils.is_cve_valid("")
    assert not utils.is_cve_valid("not-a-cve")


def test_unclassify_codestreams():
    cs_list = [
        Codestream("15.2u10"),
        Codestream("15.2u11"),
        Codestream("15.3u10"),
        Codestream("15.3u12"),
        Codestream("15.5u6"),
    ]

    # Single range expands to both codestreams
    result = utils.unclassify_codestreams("15.2u10-11", cs_list)
    assert result == [Codestream("15.2u10"), Codestream("15.2u11")]

    # Single entry without range
    result = utils.unclassify_codestreams("15.3u10", cs_list)
    assert result == [Codestream("15.3u10")]

    # Multiple groups in one string
    result = utils.unclassify_codestreams("15.2u10-11 15.3u10", cs_list)
    assert result == [Codestream("15.2u10"), Codestream("15.2u11"), Codestream("15.3u10")]

    # Group that covers codestreams not in cs_list returns only matching ones
    result = utils.unclassify_codestreams("15.3u10-12", cs_list)
    assert result == [Codestream("15.3u10"), Codestream("15.3u12")]

    # Invalid group string returns None
    assert utils.unclassify_codestreams("invalid", cs_list) is None
    assert utils.unclassify_codestreams("", cs_list) is None


def test_unclassify_codestreams_rt():
    rt_list = [
        Codestream("15.7rtu6"),
        Codestream("15.7rtu7"),
        Codestream("15.7rtu8"),
        Codestream("15.5rtu10"),
    ]

    # Single RT entry
    result = utils.unclassify_codestreams("15.7rtu6", rt_list)
    assert result == [Codestream("15.7rtu6")]

    # RT range expands correctly
    result = utils.unclassify_codestreams("15.7rtu6-8", rt_list)
    assert result == [Codestream("15.7rtu6"), Codestream("15.7rtu7"), Codestream("15.7rtu8")]

    # RT group covering entries not all in the list
    result = utils.unclassify_codestreams("15.7rtu6-8 15.5rtu10", rt_list)
    assert result == [Codestream("15.7rtu6"), Codestream("15.7rtu7"), Codestream("15.7rtu8"),
                      Codestream("15.5rtu10")]

    # Non-matching RT group returns empty (entries not in list)
    result = utils.unclassify_codestreams("15.7rtu9", rt_list)
    assert result == []


def test_unclassify_codestreams_micro():
    micro_list = [
        Codestream("6.0u0"),
        Codestream("6.0u1"),
        Codestream("6.0u2"),
    ]

    # Single MICRO entry
    result = utils.unclassify_codestreams("6.0u0", micro_list)
    assert result == [Codestream("6.0u0")]

    # MICRO range
    result = utils.unclassify_codestreams("6.0u0-2", micro_list)
    assert result == [Codestream("6.0u0"), Codestream("6.0u1"), Codestream("6.0u2")]

    # Mixed MICRO and regular codestreams
    mixed_list = micro_list + [Codestream("15.5u6")]
    result = utils.unclassify_codestreams("6.0u0-1 15.5u6", mixed_list)
    assert result == [Codestream("6.0u0"), Codestream("6.0u1"), Codestream("15.5u6")]


def test_filter_codestreams():
    cs_list = [
        Codestream("15.2u10"),
        Codestream("15.3u10"),
        Codestream("15.5u6"),
        Codestream("6.0u0"),
    ]

    # No filter returns all
    assert utils.filter_codestreams(None, cs_list) == cs_list
    assert utils.filter_codestreams("", cs_list) == cs_list

    # Exact match
    assert utils.filter_codestreams("15.2u10", cs_list) == [Codestream("15.2u10")]

    # Prefix match via regex
    result = utils.filter_codestreams("15\\.2.*", cs_list)
    assert result == [Codestream("15.2u10")]

    # Match multiple codestreams
    result = utils.filter_codestreams("15\\..*", cs_list)
    assert result == [Codestream("15.2u10"), Codestream("15.3u10"), Codestream("15.5u6")]

    # No match returns empty list
    assert not utils.filter_codestreams("99\\..*", cs_list)


def test_filter_codestreams_by_arch():
    # RT codestreams only support x86_64
    rt_cs = Codestream("15.5rtu10")
    non_rt_cs = Codestream("15.5u10")
    micro_cs = Codestream("6.0u0")

    # ppc64le: RT and MICRO are filtered out, non-RT stays
    result = utils.filter_codestreams_by_arch(["ppc64le"], [rt_cs, non_rt_cs, micro_cs])
    assert result == [non_rt_cs]

    # x86_64: all three survive
    result = utils.filter_codestreams_by_arch(["x86_64"], [rt_cs, non_rt_cs, micro_cs])
    assert result == [rt_cs, non_rt_cs, micro_cs]

    # s390x: RT is filtered out, non-RT and MICRO survive
    result = utils.filter_codestreams_by_arch(["s390x"], [rt_cs, non_rt_cs, micro_cs])
    assert result == [non_rt_cs, micro_cs]

    # Empty arch list filters everything out
    assert not utils.filter_codestreams_by_arch([], [non_rt_cs])


def _archs_as_module(archs):
    """Build a per-arch CONFIG dict in the AffectedConfig shape (state irrelevant here)."""
    return {arch: "m" for arch in archs}


def test_affected_archs():
    cs1 = Codestream("15.5u10", configs={"CONFIG_A": _archs_as_module(["x86_64", "s390x"])})
    cs2 = Codestream("15.5u11", configs={"CONFIG_B": _archs_as_module(["ppc64le"])})

    assert utils.affected_archs([cs1]) == ["s390x", "x86_64"]
    assert utils.affected_archs([cs2]) == ["ppc64le"]
    assert utils.affected_archs([cs1, cs2]) == ["ppc64le", "s390x", "x86_64"]

    # No configs → no archs
    assert utils.affected_archs([Codestream("15.5u10")]) == []


def test_preferred_arch():
    def make_cs(archs):
        return Codestream("15.5u10", configs={"CONFIG_A": _archs_as_module(archs)})

    # x86_64 is top priority
    assert utils.preferred_arch([make_cs(["x86_64", "s390x", "ppc64le"])]) == "x86_64"

    # s390x preferred over ppc64le when x86_64 absent
    assert utils.preferred_arch([make_cs(["s390x", "ppc64le"])]) == "s390x"

    # ppc64le when it's the only one
    assert utils.preferred_arch([make_cs(["ppc64le"])]) == "ppc64le"


# Helpers shared across get_lp_groups tests
LP_NAME = "bsc1234567"
CS_REGULAR = [
    Codestream("15.2u10"),
    Codestream("15.2u11"),
    Codestream("15.3u10"),
    Codestream("15.3u12"),
]
CS_RT = [
    Codestream("15.7rtu6"),
    Codestream("15.7rtu7"),
    Codestream("15.7rtu8"),
]
CS_MICRO = [
    Codestream("6.0u0"),
    Codestream("6.0u1"),
    Codestream("6.0u2"),
]


def _make_groups_file(tmp_path, monkeypatch, content):
    """Create the ccp/groups file and redirect get_workdir to the temp dir."""
    ccp_dir = tmp_path / LP_NAME / "ccp"
    ccp_dir.mkdir(parents=True)
    (ccp_dir / "groups").write_text(content)
    monkeypatch.setattr(utils, "get_workdir", lambda name: tmp_path / name)


def test_get_lp_groups_regular(tmp_path, monkeypatch):
    _make_groups_file(tmp_path, monkeypatch, "15.2u10-11\n15.3u10-12\n")
    result = utils.get_lp_groups(LP_NAME, CS_REGULAR)

    assert result == {
        "15.2u10-11": [Codestream("15.2u10"), Codestream("15.2u11")],
        "15.3u10-12": [Codestream("15.3u10"), Codestream("15.3u12")],
    }


def test_get_lp_groups_rt(tmp_path, monkeypatch):
    _make_groups_file(tmp_path, monkeypatch, "15.7rtu6-8\n")
    result = utils.get_lp_groups(LP_NAME, CS_RT)

    assert result == {
        "15.7rtu6-8": [Codestream("15.7rtu6"), Codestream("15.7rtu7"), Codestream("15.7rtu8")],
    }


def test_get_lp_groups_micro(tmp_path, monkeypatch):
    _make_groups_file(tmp_path, monkeypatch, "6.0u0-2\n")
    result = utils.get_lp_groups(LP_NAME, CS_MICRO)

    assert result == {
        "6.0u0-2": [Codestream("6.0u0"), Codestream("6.0u1"), Codestream("6.0u2")],
    }


def test_get_lp_groups_skips_unmatched_groups(tmp_path, monkeypatch):
    # "99.9u0" matches the regex but none of the codestreams in cs_list → skipped
    _make_groups_file(tmp_path, monkeypatch, "15.2u10-11\n99.9u0\n")
    result = utils.get_lp_groups(LP_NAME, CS_REGULAR)

    assert "99.9u0" not in result
    assert "15.2u10-11" in result


def test_get_lp_groups_skips_invalid_lines(tmp_path, monkeypatch):
    # Lines that don't match the regex at all are silently dropped
    _make_groups_file(tmp_path, monkeypatch, "15.2u10-11\ninvalid-line\n\n")
    result = utils.get_lp_groups(LP_NAME, CS_REGULAR)

    assert result == {
        "15.2u10-11": [Codestream("15.2u10"), Codestream("15.2u11")],
    }


def test_get_lp_groups_mixed(tmp_path, monkeypatch):
    cs_all = CS_REGULAR + CS_RT + CS_MICRO
    _make_groups_file(tmp_path, monkeypatch, "15.2u10-11\n15.7rtu6-8\n6.0u0-2\n")
    result = utils.get_lp_groups(LP_NAME, cs_all)

    assert result == {
        "15.2u10-11": [Codestream("15.2u10"), Codestream("15.2u11")],
        "15.7rtu6-8": [Codestream("15.7rtu6"), Codestream("15.7rtu7"), Codestream("15.7rtu8")],
        "6.0u0-2":    [Codestream("6.0u0"), Codestream("6.0u1"), Codestream("6.0u2")],
    }


def test_get_lp_eol():
    cs_list = [
        Codestream("15.5u20", eol="2025-11-09"),
        Codestream("15.5u21", eol="2026-01-17"),
        Codestream("15.5u22", eol="2026-02-21"),
    ]
    assert utils.get_lp_eol(cs_list) == "2026-02-21"


def test_get_lp_eol_single():
    cs_list = [Codestream("15.6u5", eol="2025-11-09")]
    assert utils.get_lp_eol(cs_list) == "2025-11-09"


def test_is_lp_eol_soon():
    from datetime import date, timedelta

    today = date.today()

    # EOL in the past
    past = (today - timedelta(days=1)).isoformat()
    assert utils.is_lp_eol_soon([Codestream("15.5u20", eol=past)])

    # EOL is today
    assert utils.is_lp_eol_soon([Codestream("15.5u20", eol=today.isoformat())])

    # EOL in 29 days
    soon = (today + timedelta(days=29)).isoformat()
    assert utils.is_lp_eol_soon([Codestream("15.5u20", eol=soon)])

    # EOL in exactly 30 days
    edge = (today + timedelta(days=30)).isoformat()
    assert utils.is_lp_eol_soon([Codestream("15.5u20", eol=edge)])

    # EOL in 31 days
    far = (today + timedelta(days=31)).isoformat()
    assert not utils.is_lp_eol_soon([Codestream("15.5u20", eol=far)])


def test_is_lp_eol_soon_uses_latest():
    from datetime import date, timedelta

    today = date.today()
    past = (today - timedelta(days=10)).isoformat()
    far = (today + timedelta(days=60)).isoformat()

    # One CS expired, but the latest EOL is far out
    cs_list = [
        Codestream("15.5u20", eol=past),
        Codestream("15.5u21", eol=far),
    ]
    assert not utils.is_lp_eol_soon(cs_list)
