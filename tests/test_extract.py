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
from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib.codestreams_data import load_codestreams
from klpbuild.plugins.extract import (
    extract,
    fix_ext_symbols,
    get_ext_symbols,
    get_klpp_symbols,
    lp_out_cleanup,
)
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


# ── fix_ext_symbols ────────────────────────────────────────────────────────────

def test_fix_ext_symbols_ibt_returns_unchanged():
    """IBT codestreams bypass all fixups and return lp_out as-is."""
    cs = Codestream("15.6u0")  # needs_ibt() == True
    lp_dat = {"ext_symbols": {"vmlinux": ["my_func"]}}
    lp_out = "int (*klpe_my_func)(void);\nstatic int (*klpe_my_func)(void);\n"
    assert fix_ext_symbols(cs, lp_dat, lp_out) == lp_out


def test_fix_ext_symbols_removes_duplicate_non_static_decls():
    """
    Core use-case: klp-ccp emits a duplicate non-static declaration alongside
    the real static one.  Both non-static copies must be erased; the static
    declaration must survive intact.
    """
    cs = Codestream("15.4u0")
    lp_dat = {"ext_symbols": {"vmlinux": ["foo"]}}
    lp_out = (
        "int (*klpe_foo)(void);\n"   # duplicate #1 – must be removed
        "int (*klpe_foo)(void);\n"   # duplicate #2 – must be removed
        "static int (*klpe_foo)(void);\n"  # real declaration – must survive
    )
    result = fix_ext_symbols(cs, lp_dat, lp_out)
    assert result.count("(*klpe_foo)") == 1
    assert "static int (*klpe_foo)(void);" in result


def test_fix_ext_symbols_hash_prefixed_line_not_removed():
    """Lines starting with '#' (e.g. macro definitions) are protected by the
    negative lookahead and must not be erased."""
    cs = Codestream("15.4u0")
    lp_dat = {"ext_symbols": {"vmlinux": ["foo"]}}
    lp_out = "#define WRAP int (*klpe_foo)(void);\n"
    result = fix_ext_symbols(cs, lp_dat, lp_out)
    assert "#define WRAP int (*klpe_foo)(void);" in result


def test_fix_ext_symbols_indented_decl_not_removed():
    """Declarations that start with whitespace (indented) are protected by the
    negative lookahead and must be left untouched."""
    cs = Codestream("15.4u0")
    lp_dat = {"ext_symbols": {"vmlinux": ["foo"]}}
    lp_out = "\tint (*klpe_foo)(void);\n"
    result = fix_ext_symbols(cs, lp_dat, lp_out)
    assert "(*klpe_foo)" in result


def test_fix_ext_symbols_symbol_name_is_exact():
    """The regex anchors on 'klpe_{sym}' exactly; a symbol whose name is a
    prefix of another must not accidentally remove the longer one."""
    cs = Codestream("15.4u0")
    lp_dat = {"ext_symbols": {"vmlinux": ["foo"]}}
    lp_out = "int (*klpe_foo)(void);\nint (*klpe_foobar)(void);\n"
    result = fix_ext_symbols(cs, lp_dat, lp_out)
    assert "(*klpe_foo)" not in result
    assert "(*klpe_foobar)" in result


def test_fix_ext_symbols_multi_word_type_removed():
    """Non-static declarations with multi-word types (e.g. 'unsigned long')
    are still matched and removed."""
    cs = Codestream("15.4u0")
    lp_dat = {"ext_symbols": {"vmlinux": ["counter"]}}
    lp_out = "unsigned long (*klpe_counter)(int x);\n"
    result = fix_ext_symbols(cs, lp_dat, lp_out)
    assert "(*klpe_counter)" not in result


def test_fix_ext_symbols_multi_module_all_processed():
    """Symbols listed under different modules in ext_symbols are all cleaned up."""
    cs = Codestream("15.4u0")
    lp_dat = {"ext_symbols": {"vmlinux": ["foo"], "nfnetlink": ["bar"]}}
    lp_out = "int (*klpe_foo)(void);\nint (*klpe_bar)(void);\n"
    result = fix_ext_symbols(cs, lp_dat, lp_out)
    assert "(*klpe_foo)" not in result
    assert "(*klpe_bar)" not in result


def test_fix_ext_symbols_percpu_scalar_type():
    """Percpu __attribute__ declaration with a scalar type is rewritten to
    'static TYPE __percpu VAR'."""
    cs = Codestream("15.4u0")
    lp_dat = {"ext_symbols": {}}
    lp_out = 'static __attribute__((section(".data..percpu" ""))) __typeof__(int) (*klpe_example);\n'
    result = fix_ext_symbols(cs, lp_dat, lp_out)
    assert "static int __percpu (*klpe_example);" in result
    assert "__attribute__" not in result


def test_fix_ext_symbols_percpu_struct_pointer_type():
    """Percpu __attribute__ declaration with a struct-pointer type is rewritten
    correctly; the full type including '*' ends up before __percpu."""
    cs = Codestream("15.4u0")
    lp_dat = {"ext_symbols": {}}
    lp_out = 'static __attribute__((section(".data..percpu" ""))) __typeof__(struct foo *) (*klpe_bar);\n'
    result = fix_ext_symbols(cs, lp_dat, lp_out)
    assert "static struct foo * __percpu (*klpe_bar);" in result
    assert "__attribute__" not in result


# ── get_ext_symbols ────────────────────────────────────────────────────────────

def test_get_ext_symbols_empty_directory(tmp_path):
    """No fun_exts / obj_exts files → empty dict."""
    assert get_ext_symbols(tmp_path) == {}


def test_get_ext_symbols_kallsyms_line(tmp_path):
    """KALLSYMS lines are parsed and stored under the correct module."""
    (tmp_path / "fun_exts").write_text("KALLSYMS sym1 var1 vmlinux\n")
    assert get_ext_symbols(tmp_path) == {"vmlinux": ["sym1"]}


def test_get_ext_symbols_klp_convert_line(tmp_path):
    """KLP_CONVERT lines are parsed the same way as KALLSYMS."""
    (tmp_path / "fun_exts").write_text("KLP_CONVERT sym2 var2 vmlinux\n")
    assert get_ext_symbols(tmp_path) == {"vmlinux": ["sym2"]}


def test_get_ext_symbols_skips_non_matching_lines(tmp_path):
    """Lines not starting with KALLSYMS or KLP_CONVERT are ignored."""
    content = "# comment\nSOMETHING sym3 var3 vmlinux\nKALLSYMS sym4 var4 vmlinux\n"
    (tmp_path / "fun_exts").write_text(content)
    result = get_ext_symbols(tmp_path)
    assert result == {"vmlinux": ["sym4"]}


def test_get_ext_symbols_dash_replaced_by_underscore(tmp_path):
    """Module names with dashes are normalised (dash → underscore)."""
    (tmp_path / "fun_exts").write_text("KALLSYMS sym5 var5 my-module\n")
    result = get_ext_symbols(tmp_path)
    assert "my_module" in result
    assert "my-module" not in result


def test_get_ext_symbols_vmlinux_stays_vmlinux(tmp_path):
    """'vmlinux' is not a module; it is kept as-is."""
    (tmp_path / "fun_exts").write_text("KALLSYMS sym6 var6 vmlinux\n")
    result = get_ext_symbols(tmp_path)
    assert "vmlinux" in result


def test_get_ext_symbols_symbols_sorted_alphabetically(tmp_path):
    """Symbols within a module are sorted by name."""
    content = "KALLSYMS zzz_sym var1 vmlinux\nKALLSYMS aaa_sym var2 vmlinux\n"
    (tmp_path / "fun_exts").write_text(content)
    result = get_ext_symbols(tmp_path)
    assert result["vmlinux"] == ["aaa_sym", "zzz_sym"]


def test_get_ext_symbols_fun_exts_and_obj_exts_combined(tmp_path):
    """Symbols from both fun_exts and obj_exts are merged."""
    (tmp_path / "fun_exts").write_text("KALLSYMS func_sym var1 vmlinux\n")
    (tmp_path / "obj_exts").write_text("KALLSYMS obj_sym var2 vmlinux\n")
    result = get_ext_symbols(tmp_path)
    assert "func_sym" in result["vmlinux"]
    assert "obj_sym" in result["vmlinux"]


def test_get_ext_symbols_grouped_by_module(tmp_path):
    """Symbols from different modules are stored under their own key."""
    content = "KALLSYMS sym_a var1 vmlinux\nKALLSYMS sym_b var2 my-mod\n"
    (tmp_path / "fun_exts").write_text(content)
    result = get_ext_symbols(tmp_path)
    assert "vmlinux" in result
    assert "my_mod" in result


# ── lp_out_cleanup ─────────────────────────────────────────────────────────────

def _make_lp_out(tmp_path, content):
    lp_out = tmp_path / "livepatch.c"
    lp_out.write_text(content)
    return lp_out


def test_lp_out_cleanup_creates_orig_file(tmp_path):
    """A .orig backup is written next to the livepatch file."""
    lp_out = _make_lp_out(tmp_path, "content\n")
    lp_out_cleanup(Codestream("15.4u0"), {"ext_symbols": {}}, lp_out, tmp_path)
    assert (tmp_path / "livepatch.c.orig").exists()


def test_lp_out_cleanup_orig_preserves_original_content(tmp_path):
    """The .orig file contains the unmodified original content."""
    original = "static __init int foo(void) {}\n"
    lp_out = _make_lp_out(tmp_path, original)
    lp_out_cleanup(Codestream("15.4u0"), {"ext_symbols": {}}, lp_out, tmp_path)
    assert (tmp_path / "livepatch.c.orig").read_text() == original


def test_lp_out_cleanup_removes_local_path_from_comments(tmp_path):
    """'from {sdir}/' prefixes in klp-ccp comments are stripped."""
    sdir = tmp_path / "kernel"
    lp_out = _make_lp_out(tmp_path, f"/* klp-ccp: from {sdir}/drivers/net/foo.c */\n")
    lp_out_cleanup(Codestream("15.4u0"), {"ext_symbols": {}}, lp_out, sdir)
    content = lp_out.read_text()
    assert str(sdir) not in content
    assert "from drivers/net/foo.c" in content


def test_lp_out_cleanup_removes_local_includes(tmp_path):
    """#include lines with the local sdir path are removed; others stay."""
    sdir = tmp_path / "kernel"
    lp_out = _make_lp_out(
        tmp_path,
        f'#include "{sdir}/include/foo.h"\n#include <linux/module.h>\n',
    )
    lp_out_cleanup(Codestream("15.4u0"), {"ext_symbols": {}}, lp_out, sdir)
    content = lp_out.read_text()
    assert f'#include "{sdir}' not in content
    assert "#include <linux/module.h>" in content


def test_lp_out_cleanup_removes_unsupported_macros(tmp_path):
    """#define lines for UNSUPPORTED_MACROS are removed."""
    lp_out = _make_lp_out(
        tmp_path,
        "#define __KERNEL__\n#define MODULE\n#define KBUILD_MODNAME foo\n",
    )
    lp_out_cleanup(Codestream("15.4u0"), {"ext_symbols": {}}, lp_out, tmp_path)
    content = lp_out.read_text()
    assert "#define __KERNEL__" not in content
    assert "#define MODULE" not in content
    assert "#define KBUILD_MODNAME" not in content


def test_lp_out_cleanup_removes_init_exit_attributes(tmp_path):
    """' __init' and ' __exit' markers are removed from function signatures."""
    lp_out = _make_lp_out(tmp_path, "static __init int foo(void)\n{\n}\n")
    lp_out_cleanup(Codestream("15.4u0"), {"ext_symbols": {}}, lp_out, tmp_path)
    assert "__init" not in lp_out.read_text()


def test_lp_out_cleanup_collapses_multiple_empty_lines(tmp_path):
    """Three or more consecutive blank lines are collapsed to one."""
    lp_out = _make_lp_out(tmp_path, "line1\n\n\n\nline2\n")
    lp_out_cleanup(Codestream("15.4u0"), {"ext_symbols": {}}, lp_out, tmp_path)
    assert "\n\n\n" not in lp_out.read_text()
