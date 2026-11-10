# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2026 SUSE
"""
Registry of the klp-ccp ``klpr_`` macros that klp-build rewrites.

klp-ccp renames some kernel macros with a ``klpr_`` prefix and emits its own
definitions for them. Some of those definitions are problematic inside a
livepatch module (e.g. jump-label static keys and static calls rely on asm-goto
jump labels and static-call trampolines, which are hard to relocate).

extract.py drops klp-ccp's ``#define`` lines for every macro listed here and
records which of them each file still uses; templ.py then emits our own
definitions in their place.

To add a new rewrite whose replacement is a fixed definition, add an entry to
``SIMPLE_MACROS``. Only rewrites that need custom logic (like static calls)
require a dedicated builder in templ.py.
"""

# Static calls need a dedicated builder in templ.py: the definition depends on
# IBT and the aliases expand to the base macro.
STATIC_CALL_BASE = "klpr_static_call"
STATIC_CALL_ALIASES = ("klpr___raw_static_call", "klpr___static_call_cond")
STATIC_CALL_MACROS = (STATIC_CALL_BASE, *STATIC_CALL_ALIASES)

# Macros replaced by a fixed definition, emitted in this order when used.
SIMPLE_MACROS = {
    # Read the static key from memory instead of relying on jump labels.
    "klpr_static_key_false": "#define klpr_static_key_false(key) static_key_enabled(key)",
    "klpr_static_key_true": "#define klpr_static_key_true(key) static_key_enabled(key)",
    # Use the kernel's might_resched() instead of klp-ccp's expansion
    "klpr_might_resched": "#define klpr_might_resched() might_resched()",
    # Use the kernel's cond_resched() instead of klp-ccp's expansion
    "klpr_cond_resched": "#define klpr_cond_resched() cond_resched()",
}

ALL_MACROS = (*STATIC_CALL_MACROS, *SIMPLE_MACROS)
