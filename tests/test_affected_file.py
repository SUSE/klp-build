# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2026 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import pytest

from klpbuild.klplib.affected_file import (
    AffectedConfig,
    AffectedFile,
    AffectedModule,
    ConfigState,
)


def test_config_state_values():
    assert ConfigState.NOT_SET.value == "n"
    assert ConfigState.MODULE.value == "m"
    assert ConfigState.BUILTIN.value == "y"


def test_config_state_from_value():
    assert ConfigState("n") is ConfigState.NOT_SET
    assert ConfigState("m") is ConfigState.MODULE
    assert ConfigState("y") is ConfigState.BUILTIN


def test_config_state_invalid_value():
    with pytest.raises(ValueError):
        ConfigState("z")


def test_config_init_requires_config_prefix():
    with pytest.raises(ValueError, match=r"missing CONFIG_ prefix"):
        AffectedConfig("FOO")


def test_config_init_default_is_empty():
    cfg = AffectedConfig("CONFIG_FOO")
    assert cfg.config_name == "CONFIG_FOO"
    assert cfg.archs() == set()
    assert not cfg.is_set()


def test_config_init_with_arch_values():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "y", "ppc64le": "m"})
    assert cfg.get_arch("x86_64") is ConfigState.BUILTIN
    assert cfg.get_arch("ppc64le") is ConfigState.MODULE
    assert cfg.get_arch("s390x") is ConfigState.NOT_SET


def test_config_init_invalid_value_in_arch_values():
    with pytest.raises(ValueError):
        AffectedConfig("CONFIG_FOO", {"x86_64": "z"})


def test_config_set_with_unknown_arch_raises():
    cfg = AffectedConfig("CONFIG_FOO")
    with pytest.raises(ValueError, match=r"Unknown arch"):
        cfg.set_arch("bogus", ConfigState.BUILTIN)


def test_config_set_not_set_removes_entry():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    assert "x86_64" in cfg.archs()
    cfg.set_arch("x86_64", ConfigState.NOT_SET)
    assert cfg.get_arch("x86_64") is ConfigState.NOT_SET
    assert "x86_64" not in cfg.archs()


def test_config_set_overwrites_existing_value():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    cfg.set_arch("x86_64", ConfigState.MODULE)
    assert cfg.get_arch("x86_64") is ConfigState.MODULE


def test_config_get_default_is_not_set():
    cfg = AffectedConfig("CONFIG_FOO")
    for arch in ("x86_64", "ppc64le", "s390x"):
        assert cfg.get_arch(arch) is ConfigState.NOT_SET


def test_config_get_with_unknown_arch_raises():
    cfg = AffectedConfig("CONFIG_FOO")
    with pytest.raises(ValueError, match=r"Unknown arch"):
        cfg.get_arch("bogus")


def test_config_archs_returns_only_set_archs():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "y", "s390x": "m"})
    assert cfg.archs() == {"x86_64", "s390x"}


def test_config_is_builtin_on_any():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "m"})
    assert not cfg.is_builtin_on_any()
    cfg.set_arch("ppc64le", ConfigState.BUILTIN)
    assert cfg.is_builtin_on_any()


def test_config_is_module_on_any():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    assert not cfg.is_module_on_any()
    cfg.set_arch("ppc64le", ConfigState.MODULE)
    assert cfg.is_module_on_any()


def test_config_is_set():
    cfg = AffectedConfig("CONFIG_FOO")
    assert not cfg.is_set()
    cfg.set_arch("x86_64", ConfigState.BUILTIN)
    assert cfg.is_set()
    cfg.set_arch("x86_64", ConfigState.NOT_SET)
    assert not cfg.is_set()


def test_config_bool_matches_is_set():
    cfg = AffectedConfig("CONFIG_FOO")
    assert not bool(cfg)
    cfg.set_arch("x86_64", ConfigState.BUILTIN)
    assert bool(cfg)


def test_config_equality():
    a = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    b = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    c = AffectedConfig("CONFIG_FOO", {"x86_64": "m"})
    d = AffectedConfig("CONFIG_BAR", {"x86_64": "y"})
    assert a == b
    assert a != c
    assert a != d
    assert a != "not-a-config"


def test_config_hashable():
    a = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    b = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    s = {a, b}
    assert len(s) == 1


def test_config_repr_contains_name_and_values():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    r = repr(cfg)
    assert "CONFIG_FOO" in r
    assert "x86_64" in r


def test_config_str_with_values():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "y"})
    assert str(cfg) == "CONFIG_FOO(x86_64=y)"


def test_config_str_empty():
    cfg = AffectedConfig("CONFIG_FOO")
    assert str(cfg) == "CONFIG_FOO(not set)"


def test_config_to_dict():
    cfg = AffectedConfig("CONFIG_FOO", {"x86_64": "y", "ppc64le": "m"})
    assert cfg.to_dict() == {"x86_64": "y", "ppc64le": "m"}


def test_config_to_dict_empty():
    assert AffectedConfig("CONFIG_FOO").to_dict() == {}


def test_config_from_dict_round_trip():
    original = AffectedConfig("CONFIG_FOO", {"x86_64": "y", "s390x": "m"})
    rebuilt = AffectedConfig.from_dict("CONFIG_FOO", original.to_dict())
    assert original == rebuilt


def test_config_from_dict_empty():
    rebuilt = AffectedConfig.from_dict("CONFIG_FOO", {})
    assert rebuilt == AffectedConfig("CONFIG_FOO")
    assert not rebuilt.is_set()


def test_module_init_defaults():
    m = AffectedModule("fs/ext4/ext4")
    assert m.name == "fs/ext4/ext4"
    assert m.supported is None
    assert m.blacklisted is False
    assert m.get_obj_path("x86_64") is None


def test_module_vmlinux_constant():
    assert AffectedModule.VMLINUX == "vmlinux"


def test_module_vmlinux_factory():
    v = AffectedModule.vmlinux()
    assert isinstance(v, AffectedModule)
    assert v.name == AffectedModule.VMLINUX
    assert v.is_vmlinux
    # vmlinux is always patchable in the klp-build sense; the factory
    # pre-marks supported=True so callers like filter_unsupported_kmodules
    # behave correctly when a vmlinux entry lands in cs.modules.
    assert v.supported is True


def test_module_is_vmlinux_false_for_regular_module():
    m = AffectedModule("fs/ext4/ext4")
    assert not m.is_vmlinux


def test_module_cache_obj_path_unknown_arch_raises():
    m = AffectedModule("foo")
    with pytest.raises(ValueError, match=r"Unknown arch"):
        m.set_obj_path("bogus", "/some/path")


def test_module_get_obj_path_unknown_arch_raises():
    m = AffectedModule("foo")
    with pytest.raises(ValueError, match=r"Unknown arch"):
        m.get_obj_path("bogus")


def test_module_cache_and_get_obj_path():
    m = AffectedModule("foo")
    m.set_obj_path("x86_64", "/path/x86")
    m.set_obj_path("s390x", "/path/s390")
    assert m.get_obj_path("x86_64") == "/path/x86"
    assert m.get_obj_path("s390x") == "/path/s390"
    assert m.get_obj_path("ppc64le") is None


def test_module_cache_overwrites_per_arch():
    m = AffectedModule("foo")
    m.set_obj_path("x86_64", "/old")
    m.set_obj_path("x86_64", "/new")
    assert m.get_obj_path("x86_64") == "/new"


def test_module_to_dict_minimal():
    m = AffectedModule("foo")
    assert m.to_dict() == {
        "supported": None,
        "blacklisted": False,
        "obj_paths": {},
    }


def test_module_to_dict_populated():
    m = AffectedModule("foo")
    m.supported = True
    m.blacklisted = True
    m.set_obj_path("x86_64", "/path/x86")
    assert m.to_dict() == {
        "supported": True,
        "blacklisted": True,
        "obj_paths": {"x86_64": "/path/x86"},
    }


def test_module_to_dict_obj_paths_is_a_copy():
    m = AffectedModule("foo")
    m.set_obj_path("x86_64", "/path/x86")
    d = m.to_dict()
    d["obj_paths"]["s390x"] = "/mutated"
    # Internal state must remain untouched
    assert m.get_obj_path("s390x") is None


def test_module_from_dict_round_trip():
    original = AffectedModule("foo")
    original.supported = True
    original.blacklisted = False
    original.set_obj_path("x86_64", "/path/x86")
    original.set_obj_path("s390x", "/path/s390")
    rebuilt = AffectedModule.from_dict("foo", original.to_dict())
    assert original == rebuilt
    assert rebuilt.supported == original.supported
    assert rebuilt.blacklisted == original.blacklisted
    assert rebuilt.get_obj_path("x86_64") == "/path/x86"
    assert rebuilt.get_obj_path("s390x") == "/path/s390"


def test_module_from_dict_round_trip_minimal():
    original = AffectedModule("foo")
    rebuilt = AffectedModule.from_dict("foo", original.to_dict())
    assert original == rebuilt
    assert rebuilt.supported is None
    assert rebuilt.blacklisted is False


def test_module_from_dict_round_trip_vmlinux():
    original = AffectedModule.vmlinux()
    original.supported = True
    original.set_obj_path("x86_64", "/boot/vmlinux-x86")
    rebuilt = AffectedModule.from_dict(AffectedModule.VMLINUX, original.to_dict())
    assert original == rebuilt
    assert rebuilt.is_vmlinux
    assert rebuilt.supported is True
    assert rebuilt.get_obj_path("x86_64") == "/boot/vmlinux-x86"


def test_module_from_dict_strict_missing_supported():
    with pytest.raises(KeyError):
        AffectedModule.from_dict("foo", {"blacklisted": False, "obj_paths": {}})


def test_module_from_dict_strict_missing_blacklisted():
    with pytest.raises(KeyError):
        AffectedModule.from_dict("foo", {"supported": True, "obj_paths": {}})


def test_module_from_dict_strict_missing_obj_paths():
    with pytest.raises(KeyError):
        AffectedModule.from_dict("foo", {"supported": True, "blacklisted": False})


def test_module_from_dict_validates_arch_in_obj_paths():
    with pytest.raises(ValueError, match=r"Unknown arch"):
        AffectedModule.from_dict("foo", {
            "supported": True,
            "blacklisted": False,
            "obj_paths": {"bogus": "/path"},
        })


def test_module_equality():
    a = AffectedModule("foo")
    b = AffectedModule("foo")
    assert a == b
    # __eq__ only compares name, so differing supported still means equal
    b.supported = True
    assert a == b
    c = AffectedModule("bar")
    assert a != c


def test_module_equality_non_module_returns_not_implemented():
    a = AffectedModule("foo")
    assert a != "not-a-module"
    assert a.__eq__("not-a-module") is NotImplemented


def test_module_hashable():
    a = AffectedModule("foo")
    b = AffectedModule("foo")
    s = {a, b}
    assert len(s) == 1


def test_module_str_returns_name():
    m = AffectedModule("fs/ext4/ext4")
    assert str(m) == "fs/ext4/ext4"
    v = AffectedModule.vmlinux()
    assert str(v) == "vmlinux"


def test_module_repr_contains_name_and_state():
    m = AffectedModule("fs/ext4/ext4")
    m.supported = True
    r = repr(m)
    assert "fs/ext4/ext4" in r
    assert "True" in r


# Helper: a fully-populated dict matching AffectedFile.to_dict()'s schema, used
# in strict-mode tests so they only differ from a valid input by the one key
# being removed.
_FILE_FULL_DICT = {
    "config_name": "CONFIG_FOO",
    "module_name": "drivers/foo",
    "affected_symbols": ["a", "b"],
    "ibt": False,
    "dup_symbols": [],
    "ext_symbols": {},
    "klpp_symbols": {},
}


def test_file_init_defaults():
    f = AffectedFile("foo.c")
    assert f.filename == "foo.c"
    assert f.config_name is None
    assert f.module_name is None
    assert f.affected_symbols == set()


def test_file_init_extraction_defaults():
    f = AffectedFile("foo.c")
    assert f.ibt is False
    assert f.dup_symbols == []
    assert f.ext_symbols == {}
    assert f.klpp_symbols == {}


def test_file_extraction_attrs_assignable():
    """Extract step writes these fields directly; verify they accept assignment."""
    f = AffectedFile("foo.c")
    f.ibt = True
    f.dup_symbols.append("dup")
    f.ext_symbols["mod"] = ["sym1", "sym2"]
    f.klpp_symbols["sym1"] = "void sym1(void)"
    assert f.ibt is True
    assert f.dup_symbols == ["dup"]
    assert f.ext_symbols == {"mod": ["sym1", "sym2"]}
    assert f.klpp_symbols == {"sym1": "void sym1(void)"}


def test_file_init_with_kwargs():
    f = AffectedFile(
        "fs/ext4/inode.c",
        config_name="CONFIG_EXT4_FS",
        module_name="fs/ext4/ext4",
        affected_symbols={"a", "b"},
    )
    assert f.filename == "fs/ext4/inode.c"
    assert f.config_name == "CONFIG_EXT4_FS"
    assert f.module_name == "fs/ext4/ext4"
    assert f.affected_symbols == {"a", "b"}


def test_file_affected_symbols_is_a_copy():
    src = {"a", "b"}
    f = AffectedFile("foo.c", affected_symbols=src)
    src.add("c")
    # Mutating the source set must not leak into the AffectedFile
    assert f.affected_symbols == {"a", "b"}


def test_file_affected_symbols_accepts_iterable():
    f = AffectedFile("foo.c", affected_symbols=("a", "b", "a"))
    assert f.affected_symbols == {"a", "b"}


def test_file_to_dict():
    f = AffectedFile(
        "foo.c",
        config_name="CONFIG_FOO",
        module_name="drivers/foo",
        affected_symbols={"b", "a"},
    )
    assert f.to_dict() == {
        "config_name": "CONFIG_FOO",
        "module_name": "drivers/foo",
        "affected_symbols": ["a", "b"],   # sorted
        "ibt": False,
        "dup_symbols": [],
        "ext_symbols": {},
        "klpp_symbols": {},
    }


def test_file_to_dict_defaults():
    assert AffectedFile("foo.c").to_dict() == {
        "config_name": None,
        "module_name": None,
        "affected_symbols": [],
        "ibt": False,
        "dup_symbols": [],
        "ext_symbols": {},
        "klpp_symbols": {},
    }


def test_file_to_dict_with_extraction_data():
    f = AffectedFile("foo.c", config_name="CONFIG_FOO", module_name="drivers/foo")
    f.ibt = True
    f.dup_symbols = ["dup1", "dup2"]
    f.ext_symbols = {"drivers/foo": ["bar", "baz"]}
    f.klpp_symbols = {"bar": "int bar(void)"}
    d = f.to_dict()
    assert d["ibt"] is True
    assert d["dup_symbols"] == ["dup1", "dup2"]
    assert d["ext_symbols"] == {"drivers/foo": ["bar", "baz"]}
    assert d["klpp_symbols"] == {"bar": "int bar(void)"}


def test_file_to_dict_extraction_collections_are_copies():
    """Mutating the dict returned by to_dict() must not affect internal state."""
    f = AffectedFile("foo.c")
    f.dup_symbols.append("a")
    f.ext_symbols["mod"] = ["x"]
    f.klpp_symbols["s"] = "p"
    d = f.to_dict()
    d["dup_symbols"].append("mutated")
    d["ext_symbols"]["new_mod"] = []
    d["klpp_symbols"]["new_sym"] = ""
    assert f.dup_symbols == ["a"]
    assert f.ext_symbols == {"mod": ["x"]}
    assert f.klpp_symbols == {"s": "p"}


def test_file_from_dict_round_trip():
    original = AffectedFile(
        "fs/ext4/inode.c",
        config_name="CONFIG_EXT4_FS",
        module_name="fs/ext4/ext4",
        affected_symbols={"x", "y", "z"},
    )
    rebuilt = AffectedFile.from_dict("fs/ext4/inode.c", original.to_dict())
    assert rebuilt.filename == original.filename
    assert rebuilt.config_name == original.config_name
    assert rebuilt.module_name == original.module_name
    assert rebuilt.affected_symbols == original.affected_symbols
    # Extraction-phase defaults round-trip too
    assert rebuilt.ibt == original.ibt
    assert rebuilt.dup_symbols == original.dup_symbols
    assert rebuilt.ext_symbols == original.ext_symbols
    assert rebuilt.klpp_symbols == original.klpp_symbols


def test_file_from_dict_round_trip_defaults():
    original = AffectedFile("foo.c")
    rebuilt = AffectedFile.from_dict("foo.c", original.to_dict())
    assert rebuilt.filename == original.filename
    assert rebuilt.config_name is None
    assert rebuilt.module_name is None
    assert rebuilt.affected_symbols == set()
    assert rebuilt.ibt is False
    assert rebuilt.dup_symbols == []
    assert rebuilt.ext_symbols == {}
    assert rebuilt.klpp_symbols == {}


def test_file_from_dict_round_trip_with_extraction():
    original = AffectedFile(
        "fs/ext4/inode.c",
        config_name="CONFIG_EXT4_FS",
        module_name="fs/ext4/ext4",
        affected_symbols={"x"},
    )
    original.ibt = True
    original.dup_symbols = ["dup_a", "dup_b"]
    original.ext_symbols = {"fs/ext4/ext4": ["sym1", "sym2"]}
    original.klpp_symbols = {"sym1": "int sym1(void)"}
    rebuilt = AffectedFile.from_dict("fs/ext4/inode.c", original.to_dict())
    assert rebuilt.ibt is True
    assert rebuilt.dup_symbols == ["dup_a", "dup_b"]
    assert rebuilt.ext_symbols == {"fs/ext4/ext4": ["sym1", "sym2"]}
    assert rebuilt.klpp_symbols == {"sym1": "int sym1(void)"}


def test_file_from_dict_strict_missing_config_name():
    data = {k: v for k, v in _FILE_FULL_DICT.items() if k != "config_name"}
    with pytest.raises(KeyError):
        AffectedFile.from_dict("foo.c", data)


def test_file_from_dict_strict_missing_module_name():
    data = {k: v for k, v in _FILE_FULL_DICT.items() if k != "module_name"}
    with pytest.raises(KeyError):
        AffectedFile.from_dict("foo.c", data)


def test_file_from_dict_strict_missing_affected_symbols():
    data = {k: v for k, v in _FILE_FULL_DICT.items() if k != "affected_symbols"}
    with pytest.raises(KeyError):
        AffectedFile.from_dict("foo.c", data)


def test_file_from_dict_strict_missing_ibt():
    data = {k: v for k, v in _FILE_FULL_DICT.items() if k != "ibt"}
    with pytest.raises(KeyError):
        AffectedFile.from_dict("foo.c", data)


def test_file_from_dict_strict_missing_dup_symbols():
    data = {k: v for k, v in _FILE_FULL_DICT.items() if k != "dup_symbols"}
    with pytest.raises(KeyError):
        AffectedFile.from_dict("foo.c", data)


def test_file_from_dict_strict_missing_ext_symbols():
    data = {k: v for k, v in _FILE_FULL_DICT.items() if k != "ext_symbols"}
    with pytest.raises(KeyError):
        AffectedFile.from_dict("foo.c", data)


def test_file_from_dict_strict_missing_klpp_symbols():
    data = {k: v for k, v in _FILE_FULL_DICT.items() if k != "klpp_symbols"}
    with pytest.raises(KeyError):
        AffectedFile.from_dict("foo.c", data)


def test_file_from_dict_rebuilds_set_from_list():
    data = dict(_FILE_FULL_DICT)
    data["affected_symbols"] = ["a", "b", "a"]
    rebuilt = AffectedFile.from_dict("foo.c", data)
    assert rebuilt.affected_symbols == {"a", "b"}


def test_file_from_dict_extraction_collections_are_copies():
    """from_dict must not retain references to the input dict's lists/dicts."""
    src_dup = ["a"]
    src_ext = {"mod": ["x"]}
    src_klpp = {"s": "p"}
    data = dict(_FILE_FULL_DICT)
    data["dup_symbols"] = src_dup
    data["ext_symbols"] = src_ext
    data["klpp_symbols"] = src_klpp
    rebuilt = AffectedFile.from_dict("foo.c", data)
    src_dup.append("mutated")
    src_ext["new_mod"] = []
    src_klpp["new_sym"] = ""
    assert rebuilt.dup_symbols == ["a"]
    assert rebuilt.ext_symbols == {"mod": ["x"]}
    assert rebuilt.klpp_symbols == {"s": "p"}


def test_file_equality():
    a = AffectedFile("foo.c", config_name="CONFIG_FOO")
    b = AffectedFile("foo.c", config_name="CONFIG_BAR")
    c = AffectedFile("bar.c", config_name="CONFIG_FOO")
    assert a == b      # equality is filename-based
    assert a != c
    assert a != "not-a-file"
    assert a.__eq__("not-a-file") is NotImplemented


def test_file_hashable():
    a = AffectedFile("foo.c")
    b = AffectedFile("foo.c")
    s = {a, b}
    assert len(s) == 1


def test_file_repr_contains_identity_and_keys():
    f = AffectedFile("foo.c", config_name="CONFIG_FOO", module_name="drivers/foo")
    r = repr(f)
    assert "foo.c" in r
    assert "CONFIG_FOO" in r
    assert "drivers/foo" in r
