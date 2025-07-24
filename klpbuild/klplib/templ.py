# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from datetime import datetime
from pathlib import Path

from mako.lookup import TemplateLookup
from mako.template import Template

from klpbuild.klplib.bugzilla import get_bug_title
from klpbuild.klplib.codestreams_data import get_codestreams_data
from klpbuild.klplib.utils import ARCHS, fix_mod_string, get_mail, get_workdir, get_lp_number, get_fname


MACRO_PROTO_SYMS = """\
<%
def get_protos(proto_syms):
        proto_list = []

        if not proto_syms:
            return ''

        for fname, data in proto_syms.items():
            proto_list.append(f"int {fname}_init(void);")
            if data["cleanup"]:
                proto_list.append(f"void {fname}_cleanup(void);\\n")
            else:
                proto_list.append(f"static inline void {fname}_cleanup(void);\\n")

        return '\\n' + '\\n'.join(proto_list)
%>\
"""


TEMPL_NO_SYMS_H = """\
#ifndef _${ fname.upper() }_H
#define _${ fname.upper() }_H

static inline int ${ fname }_init(void) { return 0; }
static inline void ${ fname }_cleanup(void) {}

#endif /* _${ fname.upper() }_H */
"""


TEMPL_H = """\
#ifndef _${ fname.upper() }_H
#define _${ fname.upper() }_H

% if check_enabled:
#if IS_ENABLED(${ config })

int ${ fname }_init(void);
% if has_cleanup:
void ${ fname }_cleanup(void);
% else:
static inline void ${ fname }_cleanup(void) {}
% endif %
${get_protos(proto_syms)}
#else /* !IS_ENABLED(${ config }) */

static inline int ${ fname }_init(void) { return 0; }
static inline void ${ fname }_cleanup(void) {}

#endif /* IS_ENABLED(${ config }) */

% else:
int ${ fname }_init(void);
% if has_cleanup:
void ${ fname }_cleanup(void);
% else:
static inline void ${ fname }_cleanup(void) {}
% endif
${get_protos(proto_syms)}
% endif
#endif /* _${ fname.upper() }_H */
"""

TEMPL_SUSE_HEADER = """\
/*
 * ${fname}
 *
 * Fix for CVE-${cve}, bsc#${lp_num}
 *
 *  Copyright (c) ${year} SUSE
 *  Author: ${ user } <${ email }>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
"""

TEMPL_GET_EXTS = """\
<%
def get_exts(ibt_mod, ext_vars):
        ext_list = []
        for obj, syms in ext_vars.items():
            if obj == 'vmlinux':
                mod = ''
            else:
                mod = obj

            # ibt_mod is only used with IBT
            if not ibt_mod:
                for sym in syms:
                    lsym = f'\\t{{ "{sym}",'
                    prefix_var = f'klpe_{sym}'
                    if not mod:
                        var = f' (void *)&{prefix_var} }},'
                    else:
                        var = f' (void *)&{prefix_var},'
                        mod = f' "{obj}" }},'

                    # 73 here is because a tab is 8 spaces, so 72 + 8 == 80, which is
                    # our goal when splitting these lines
                    if len(lsym + var + mod) < 73:
                        ext_list.append(lsym + var + mod)

                    elif len(lsym + var) < 73:
                        ext_list.append(lsym + var)
                        if mod:
                            ext_list.append('\\t ' + mod)

                    else:
                        ext_list.append(lsym)
                        if len(var + mod) < 73:
                            ext_list.append(f'\\t {var}{mod}')
                        else:
                            ext_list.append(f'\\t {var}')
                            if mod:
                                ext_list.append(f'\\t {mod}')
            else:
                for sym in syms:
                    start = f"extern typeof({sym})"
                    lsym = f"{sym}"
                    end = f"KLP_RELOC_SYMBOL({ibt_mod}, {obj}, {sym});"

                    if len(start + lsym + end) < 80:
                        ext_list.append(f"{start} {lsym} {end}")

                    elif len(start + lsym) < 80:
                        ext_list.append(f"{start} {lsym}")
                        ext_list.append(f"\\t {end}")

                    else:
                        ext_list.append(start)
                        if len(lsym + end) < 80:
                            ext_list.append(f"\\t {lsym} {end}")
                        else:
                            ext_list.append(f"\\t {lsym}")
                            ext_list.append(f"\\t {end}")

        return '\\n'.join(ext_list)
%>
"""

TEMPL_PATCH_VMLINUX = """\
% if check_enabled:
#if IS_ENABLED(${ config })
% endif # check_enabled

<%include file="${ inc_src_file }"/>

#include "livepatch_${ lp_name }.h"

% if ext_vars:
% if ibt:
#include <linux/livepatch.h>

${get_exts("vmlinux", ext_vars)}
% else: # ibt
#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
${get_exts("", ext_vars)}
};

int ${ fname }_init(void)
{
% if mod_mutex:
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
% else: # mod_mutex
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
% endif # mod_mutex
}

% endif # ibt
% endif # ext_vars
% if check_enabled:

#endif /* IS_ENABLED(${ config }) */
% endif # check_enabled
"""

TEMPL_PATCH_MODULE = """\
% if check_enabled:
#if IS_ENABLED(${ config })

#if !IS_MODULE(${ config })
#error "Live patch supports only CONFIG=m"
#endif
% endif # check_enabled

<%include file="${ inc_src_file }"/>

#include "livepatch_${ lp_name }.h"

% if ext_vars:
% if ibt:
#include <linux/livepatch.h>

${get_exts(mod, ext_vars)}
% else: # ibt
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "${ mod }"

static struct klp_kallsyms_reloc klp_funcs[] = {
${get_exts("", ext_vars)}
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
% if mod_mutex:
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
% else: # mod_mutex
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
% endif # mod_mutex

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int ${ fname }_init(void)
{
	int ret;
% if mod_mutex:

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
% else: # mod_mutex
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
% endif # mod_mutex
}

void ${ fname }_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
% endif # ibt
% endif # ext_vars
% if check_enabled:

#endif /* IS_ENABLED(${ config }) */
% endif # check_enabled
"""

TEMPL_HOLLOW = """\
% if check_enabled:
#if IS_ENABLED(${ config })
% endif # check_enabled

#include "livepatch_${ lp_name }.h"

int ${ fname }_init(void)
{
\treturn 0;
}

void ${ fname }_cleanup(void)
{
}

% if check_enabled:

#endif /* IS_ENABLED(${ config }) */
% endif # check_enabled
"""

TEMPL_COMMIT = """\
Fix for CVE-${cve} ("${title}")

Live patch for CVE-${cve}. ${msg}:
% for cmsg in commits:
- ${cmsg}
% endfor

KLP: CVE-${cve}
References: bsc#${ lp_name } CVE-${cve}
Signed-off-by: ${user} <${email}>
"""

TEMPL_KBUILD = """\
<%
from pathlib import PurePath
def get_entries(lpdir, bsc, cs):
    ret = []
    for entry in lpdir.iterdir():
        fname = entry.name
        if not fname.endswith('.c'):
            continue

        # Add both the older and the new format to apply flags to objects
        fname = PurePath(fname).with_suffix('.o')
        ret.append(f'CFLAGS_{fname} += -Werror')
        fname = f'{bsc}/{fname}'
        ret.append(f'CFLAGS_{fname} += -Werror')

    return "\\n".join(ret)
%>\
${get_entries(lpdir, bsc, cs)}
"""

TEMPL_PATCHED = """\
<%
def get_patched(cs_files, check_enabled):
    ret = []
    for ffile, fdata in cs_files.items():
        conf = ''
        if check_enabled and fdata['conf']:
            conf = f' IS_ENABLED({fdata["conf"]})'

        mod = fdata['module'].replace('-', '_')
        for func in fdata['symbols']:
            ret.append(f'{mod} {func} klpp_{func}{conf}')

    return "\\n".join(ret)
%>\
${get_patched(cs_files, check_enabled)}
"""


def preproc_slashes(text):
    txt = r"<%! BS='\\' %>" + text.replace("\\", "${BS}")
    return r"<%! HASH='##' %>" + txt.replace("##", "${HASH}")

def __generate_patched_conf(lp_name, cs):
    render_vars = {"cs_files": cs.files, "check_enabled": _is_check_enabled()}
    with open(Path(cs.get_lp_dir(lp_name), "patched_funcs.csv"), "w") as f:
        f.write(Template(TEMPL_PATCHED).render(**render_vars))

def __generate_header_file(lp_name, lp_path, cs):
    out_name = f"livepatch_{lp_name}.h"
    render_vars = {
        "fname": get_fname(out_name),
    }

    # We don't need any setups on IBT besides the livepatch_init/cleanup ones
    header_templ = TEMPL_NO_SYMS_H

    if not cs.needs_ibt:
        configs = set()
        config = ""
        has_cleanup = False
        proto_syms = {}

        for src_file, data in cs.files.items():
            configs.add(data["conf"])
            # If we have external symbols we need an init function to load them. If the module
            # isn't vmlinux then we also need an _exit function
            if data["ext_symbols"]:
                if data["module"] != "vmlinux":
                    # Used by the livepatch_cleanup
                    has_cleanup = True

                proto_fname = get_fname(cs.lp_out_file(lp_name, src_file))
                proto_syms[proto_fname] = {"cleanup": data["module"] != "vmlinux"}

        # If we don't have any external symbols then we don't need the empty _init/_exit functions
        if proto_syms.keys():
            # Only populate the config check in the header if the livepatch is
            # patching code under only one config. Otherwise let the developer to
            # fill it.
            if len(configs) == 1:
                config = configs.pop()

            # We there was only one entry in the proto_syms means that we have only one file in
            # in this livepatch, so we are already covered
            # Situations where we don't need any extra symbol prototypes:
            # * we don't have any externalized symbols
            # * the livepatch has only one file (_init/_cleanup for livepatch_ are created by default)
            if len(proto_syms.keys()) == 1 and len(cs.files.keys()) == 1:
                proto_syms = {}

            render_vars.update({
                "check_enabled": _is_check_enabled(),
                "config": config,
                "has_cleanup": has_cleanup,
                "proto_syms": proto_syms,
            })

            header_templ = MACRO_PROTO_SYMS + TEMPL_H

    with open(Path(lp_path, out_name), "w") as f:
        lpdir = TemplateLookup(directories=[Path()], preprocessor=preproc_slashes)
        f.write(Template(header_templ, lookup=lpdir).render(**render_vars))

def __generate_lp_file(lp_name, lp_path, cs, src_file, out_name):
    cve = get_codestreams_data('cve')
    if not cve:
        cve = "XXXX-XXXX"
    user, email = get_mail()
    tvars = {
        "check_enabled": _is_check_enabled(),
        "upstream": get_codestreams_data('upstream'),
        "config": "CONFIG_CHANGE_ME",
        "cve": cve,
        "email": email,
        "fname": get_fname(out_name),
        "include_header": "livepatch_" in out_name,
        "lp_name": lp_name,
        "lp_num": get_lp_number(lp_name),
        "user": user,
        "year": datetime.today().year,
    }

    # If we have multiple source files for the same livepatch,
    # create one hollow file to wire-up the multiple _init and
    # _clean functions
    #
    # If we are patching a module, we should have the
    # module_notifier armed to signal whenever the module comes on
    # in order to do the symbol lookups. Otherwise only _init is
    # needed, and only if there are externalized symbols being used.
    if not src_file:
        temp_str = TEMPL_HOLLOW
        lp_inc_dir = Path("non-existent")
    else:
        fdata = cs.files[str(src_file)]
        tvars.update({
            "config": fdata.get("conf", ""),
            "ext_vars": fdata.get("ext_symbols", ""),
            "ibt": fdata.get("ibt", False),
            "inc_src_file": cs.lp_out_file(lp_name, src_file),
            "mod": fix_mod_string(fdata.get("module", "")),
            "mod_mutex": cs.is_mod_mutex(),
        })

        if tvars["mod"]:
            temp_str = TEMPL_GET_EXTS + TEMPL_PATCH_MODULE
        else:
            temp_str = TEMPL_GET_EXTS + TEMPL_PATCH_VMLINUX
        lp_inc_dir = cs.get_ccp_work_dir(lp_name, src_file)

    lpdir = TemplateLookup(directories=[lp_inc_dir], preprocessor=preproc_slashes)
    with open(Path(lp_path, out_name), "w") as f:
        f.write(Template(TEMPL_SUSE_HEADER + temp_str, lookup=lpdir).render(**tvars))

def generate_livepatches(lp_name, cs):
    lp_path = cs.get_lp_dir(lp_name)
    lp_path.mkdir(exist_ok=True)

    files = cs.files
    is_multi_files = len(files.keys()) > 1

    __generate_patched_conf(lp_name, cs)

    # If there are more then one source file, we cannot fully infer what are
    # the correct configs and mods to be livepatched, so leave the mod and
    # config entries empty
    __generate_header_file(lp_name, lp_path, cs)

    # Run the template engine for each generated source file.
    for src_file, _ in files.items():
        # if use_src_name is True, the final file will be:
        #       bscXXXXXXX_{src_name}.c
        # else:
        #       livepatch_bscXXXXXXXX.c
        out_name = f"livepatch_{lp_name}.c" if not is_multi_files else \
            cs.lp_out_file(lp_name, src_file)

        __generate_lp_file(lp_name, lp_path, cs, src_file, out_name)

    # One additional file to encapsulate the _init and _clenaup methods
    # of the other source files
    if is_multi_files:
        __generate_lp_file(lp_name, lp_path, cs, None, f"livepatch_{lp_name}.c")

    create_kbuild(lp_name, cs)


def _is_check_enabled():
    # Require the IS_ENABLED ifdef guard whenever we have a livepatch that
    # is not enabled on all architectures
    return get_codestreams_data('archs') != ARCHS


def create_kbuild(lp_name, cs):
    # Create Kbuild.inc file adding an entry for all generated livepatch files.
    render_vars = {"bsc": lp_name, "cs": cs, "lpdir": cs.get_lp_dir(lp_name)}
    with open(Path(cs.get_lp_dir(lp_name), "Kbuild.inc"), "w") as f:
        f.write(Template(TEMPL_KBUILD).render(**render_vars))


def generate_commit_msg_file(lp_name):
    cmts = get_codestreams_data('upstream')
    cve = get_codestreams_data('cve')
    if not cve:
        cve = "XXXX-XXXX"
    user, email = get_mail()
    render_vars = {
        "lp_name": lp_name.replace("bsc", ""),
        "user": user,
        "email": email,
        "cve": cve,
        "commits": cmts,
        "msg": "Upstream commits" if len(cmts) > 1 else "Upstream commit",
        "title": get_bug_title(get_lp_number(lp_name)),
    }
    with open(get_workdir(lp_name)/"commit.msg", "w") as f:
        f.write(Template(TEMPL_COMMIT).render(**render_vars))
