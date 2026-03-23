# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect
import json
import logging

import pytest

import tests.utils as tests_utils
from klpbuild.klplib import utils
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.plugins.extract import extract, get_klpp_symbols
from klpbuild.plugins.setup import run as setup


def test_get_klpp_symbols_missing_patched_funcs(tmp_path):
    """RuntimeError when patched_funcs file does not exist."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text("")

    with pytest.raises(RuntimeError, match="File not found"):
        get_klpp_symbols(tmp_path, lp_out)


def test_get_klpp_symbols_no_static_no_match(tmp_path, caplog):
    """Regex requires 'static': function without it is not matched → warning."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text("int klpp_foo(void)\n{\n    return 0;\n}\n")
    (tmp_path / "patched_funcs").write_text("foo\n")

    with caplog.at_level(logging.WARNING):
        result = get_klpp_symbols(tmp_path, lp_out)

    assert not result
    assert "Failed to find klpp_foo" in caplog.text


def test_get_klpp_symbols_simple_return_type(tmp_path):
    """Basic match: scalar return type, simple params."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text("static int klpp_foo(int a, int b)\n{\n    return a + b;\n}\n")
    (tmp_path / "patched_funcs").write_text("foo\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert result == {"foo": "int klpp_foo(int a, int b);"}
    assert "static" not in lp_out.read_text()


def test_get_klpp_symbols_pointer_return_type(tmp_path):
    """Return type with * is captured by [\\w\\*] in the regex."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text("static char *klpp_foo(void)\n{\n    return NULL;\n}\n")
    (tmp_path / "patched_funcs").write_text("foo\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert result == {"foo": "char *klpp_foo(void);"}


def test_get_klpp_symbols_multiword_return_type(tmp_path):
    """Multi-word return type (e.g. 'unsigned long') is fully captured."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text("static unsigned long klpp_foo(int x)\n{\n    return 0;\n}\n")
    (tmp_path / "patched_funcs").write_text("foo\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert result == {"foo": "unsigned long klpp_foo(int x);"}


def test_get_klpp_symbols_const_struct_pointer_return(tmp_path):
    """const struct pointer return type is handled correctly."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text(
        "static const struct foo *klpp_bar(struct foo *p)\n{\n    return p;\n}\n"
    )
    (tmp_path / "patched_funcs").write_text("bar\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert result == {"bar": "const struct foo *klpp_bar(struct foo *p);"}


def test_get_klpp_symbols_multiline_via_re_s(tmp_path):
    """re.S flag lets the regex span a newline between return type and name."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text("static int\nklpp_baz(int a)\n{\n    return a;\n}\n")
    (tmp_path / "patched_funcs").write_text("baz\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert "baz" in result
    # Whitespace normalization must collapse the newline in the prototype
    assert "\n" not in result["baz"]
    assert result["baz"] == "int klpp_baz(int a);"


def test_get_klpp_symbols_params_with_pointer(tmp_path):
    """Pointer parameters (e.g. 'int *p') are preserved inside [^)]* ."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text(
        "static int klpp_foo(int *p, struct bar *q)\n{\n    return 0;\n}\n"
    )
    (tmp_path / "patched_funcs").write_text("foo\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert result == {"foo": "int klpp_foo(int *p, struct bar *q);"}


def test_get_klpp_symbols_function_pointer_param(tmp_path):
    """Function-pointer parameter '(*cb)(void)' is matched in full."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text("static int klpp_foo(int (*cb)(void))\n{\n    return 0;\n}\n")
    (tmp_path / "patched_funcs").write_text("foo\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert result == {"foo": "int klpp_foo(int (*cb)(void));"}


def test_get_klpp_symbols_strips_init_exit(tmp_path):
    r"""__init and __exit are part of ([\w\*]\s*)* and stripped from the proto."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text(
        "static int __init klpp_foo(void)\n{\n    return 0;\n}\n"
        "static void __exit klpp_bar(void)\n{\n}\n"
    )
    (tmp_path / "patched_funcs").write_text("foo\nbar\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert "__init" not in result["foo"]
    assert "__exit" not in result["bar"]


def test_get_klpp_symbols_multiple_symbols(tmp_path):
    """All matched symbols collected; unmatched one skipped."""
    lp_out = tmp_path / "lp.c"
    lp_out.write_text(
        "static int klpp_alpha(void)\n{\n    return 0;\n}\n"
        "static void klpp_beta(int x)\n{\n}\n"
    )
    (tmp_path / "patched_funcs").write_text("alpha\nbeta\ngamma\n")

    result = get_klpp_symbols(tmp_path, lp_out)

    assert "alpha" in result
    assert "beta" in result
    assert "gamma" not in result


def test_compile_commands_enoent():
    """
    Check if the extraction fails when a file isn't found on
    compile_commands.json file
    """

    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.6u16"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": {utils.ARCH},
        "conf": "CONFIG_HID",
        "module": "vmlinux",
        "file_funcs": [["drivers/hid/hid-core.c", "hid_alloc_report_buf"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    # rename the entry on files to a filename that doesn't exists (hid_core.c)
    data = tests_utils.get_codestreams_file(lp)
    file_funcs = data["codestreams"][cs]["files"].pop("drivers/hid/hid-core.c")
    data["codestreams"][cs]["files"]["drivers/hid/hid_core.c"] = file_funcs

    # write back the changed codestreams.json file
    with open(utils.get_workdir(lp) / "codestreams.json", "r+") as f:
        f.seek(0)
        f.write(json.dumps(data, indent=4))
        f.truncate()

    # reload the codestreams after the change
    load_codestreams(lp)

    # Now it should fail with hid_core.c that doesn't exists on compile_commands.json
    with pytest.raises(
        RuntimeError,
        match=r"Couldn't find cmdline for drivers/hid/hid_core.c on.*compile_commands.json. Aborting",
    ):
        extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])


def test_detect_opt_clone(caplog):
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    cs = "15.4u45"

    setup_args = {
        "lp_name": lp,
        "lp_filter": cs,
        "no_check": True,
        "archs": {utils.ARCH},
        "conf": "CONFIG_BT",
        "module": "bluetooth",
        "file_funcs": [["net/bluetooth/l2cap_sock.c", "l2cap_sock_kill"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        "full_checks": False,
    }
    setup(**setup_args)

    with caplog.at_level(logging.WARNING):
        extract(lp_name=lp, lp_filter=cs, no_patches=True, avoid_ext=[])

    assert "Symbol l2cap_sock_kill contains optimized clone" in caplog.text
