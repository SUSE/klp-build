# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from datetime import datetime
from pathlib import Path

from mako.lookup import TemplateLookup
from mako.template import Template

from klpbuild.config import Config
from klpbuild.utils import ARCHS, fix_mod_string, get_mail

TEMPL_H = """\
#ifndef _${ fname.upper() }_H
#define _${ fname.upper() }_H

% if check_enabled:
#if IS_ENABLED(${ config })
% endif

int ${ fname }_init(void);
% if mod:
void ${ fname }_cleanup(void);
% else:
static inline void ${ fname }_cleanup(void) {}
% endif %

% for p in proto_files:
<%include file="${ p }"/>
% endfor

% if check_enabled:
#else /* !IS_ENABLED(${ config }) */
% endif

static inline int ${ fname }_init(void) { return 0; }
static inline void ${ fname }_cleanup(void) {}

% if check_enabled:
#endif /* IS_ENABLED(${ config }) */
% endif

#endif /* _${ fname.upper() }_H */
"""

TEMPL_SUSE_HEADER = """\
<%
def get_commits(cmts, cs):
    if not cmts.get(cs, ''):
        return ' *  Not affected'

    ret = []
    for commit, msg in cmts[cs].items():
        if not msg:
            ret.append(' *  Not affected')
        else:
            for m in msg:
                ret.append(f' *  {m}')

    return "\\n".join(ret)
%>\
/*
 * ${fname}
 *
 * Fix for CVE-${cve}, bsc#${lp_num}
 *
% if include_header:
 *  Upstream commit:
${get_commits(commits, 'upstream')}
 *
 *  SLE12-SP5 commit:
${get_commits(commits, '12.5')}
 *
 *  SLE15-SP2 and -SP3 commit:
${get_commits(commits, 'cve-5.3')}
 *
 *  SLE15-SP4 and -SP5 commit:
${get_commits(commits, '15.4')}
 *
 *  SLE15-SP6 commit:
${get_commits(commits, '15.6')}
 *
 *  SLE MICRO-6-0 commit:
${get_commits(commits, '6.0')}
 *
% endif
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
Fix for CVE-${cve} ("CHANGE ME!")

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


class TemplateGen(Config):
    def __init__(self, lp_name):
        super().__init__(lp_name)

        # Require the IS_ENABLED ifdef guard whenever we have a livepatch that
        # is not enabled on all architectures
        self.check_enabled = self.cs_data.archs != ARCHS
        self.lp_name = lp_name

    @staticmethod
    def preproc_slashes(text):
        txt = r"<%! BS='\\' %>" + text.replace("\\", "${BS}")
        return r"<%! HASH='##' %>" + txt.replace("##", "${HASH}")

    def __generate_patched_conf(self, cs):
        render_vars = {"cs_files": cs.files, "check_enabled": self.check_enabled}
        with open(Path(cs.lpdir(), "patched_funcs.csv"), "w") as f:
            f.write(Template(TEMPL_PATCHED).render(**render_vars))

    def __generate_header_file(self, lp_path, cs):
        out_name = f"livepatch_{cs.lp_name}.h"

        lp_inc_dir = Path()
        proto_files = []
        configs = set()
        config = ""
        mod = ""

        for f, data in cs.files.items():
            configs.add(data["conf"])
            # At this point we only care to know if we are livepatching a module
            # or not, so we can overwrite the module.
            mod = data["module"]

        # Only add the inc_dir if CE is used, since it's the only backend that
        # produces the proto.h headers
        if len(proto_files) > 0:
            lp_inc_dir = cs.dir()

        # Only populate the config check in the header if the livepatch is
        # patching code under only one config. Otherwise let the developer to
        # fill it.
        if len(configs) == 1:
            config = configs.pop()

        render_vars = {
            "fname": str(Path(out_name).with_suffix("")).replace("-", "_"),
            "check_enabled": self.check_enabled,
            "proto_files": proto_files,
            "config": config,
            "mod": mod,
        }

        with open(Path(lp_path, out_name), "w") as f:
            lpdir = TemplateLookup(directories=[lp_inc_dir], preprocessor=TemplateGen.preproc_slashes)
            f.write(Template(TEMPL_H, lookup=lpdir).render(**render_vars))

    def __generate_lp_file(self, lp_path, cs, src_file, use_src_name=False):
        if src_file:
            lp_inc_dir = str(cs.work_dir(src_file))
            lp_file = cs.lp_out_file(src_file)
            fdata = cs.files[str(src_file)]
        else:
            lp_inc_dir = Path("non-existent")
            lp_file = None
            fdata = {}

        # if use_src_name is True, the final file will be:
        #       bscXXXXXXX_{src_name}.c
        # else:
        #       livepatch_bscXXXXXXXX.c
        if use_src_name:
            out_name = lp_file
        else:
            out_name = f"livepatch_{cs.lp_name}.c"

        user, email = get_mail()
        tvars = {
            "include_header": "livepatch_" in out_name,
            "cve": self.cs_data.cve if self.cs_data.cve else "XXXX-XXXX",
            "lp_name": cs.lp_name,
            "lp_num": cs.lp_name.replace("bsc", ""),
            "fname": str(Path(out_name).with_suffix("")).replace("-", "_"),
            "year": datetime.today().year,
            "user": user,
            "email": email,
            "config": fdata.get("conf", ""),
            "mod": fix_mod_string(fdata.get("module", "")),
            "mod_mutex": cs.is_mod_mutex(),
            "check_enabled": self.check_enabled,
            "ext_vars": fdata.get("ext_symbols", ""),
            "inc_src_file": lp_file,
            "ibt": fdata.get("ibt", False),
            "commits": self.cs_data.commits
        }

        with open(Path(lp_path, out_name), "w") as f:
            lpdir = TemplateLookup(directories=[lp_inc_dir], preprocessor=TemplateGen.preproc_slashes)

            # If we have multiple source files for the same livepatch,
            # create one hollow file to wire-up the multiple _init and
            # _clean functions
            #
            # If we are patching a module, we should have the
            # module_notifier armed to signal whenever the module comes on
            # in order to do the symbol lookups. Otherwise only _init is
            # needed, and only if there are externalized symbols being used.
            if not lp_file:
                temp_str = TEMPL_HOLLOW
            elif tvars["mod"]:
                temp_str = TEMPL_GET_EXTS + TEMPL_PATCH_MODULE
            else:
                temp_str = TEMPL_GET_EXTS + TEMPL_PATCH_VMLINUX

            f.write(Template(TEMPL_SUSE_HEADER + temp_str, lookup=lpdir).render(**tvars))

    def generate_livepatches(self, cs):
        lp_path = cs.lpdir()
        lp_path.mkdir(exist_ok=True)

        files = cs.files
        is_multi_files = len(files.keys()) > 1

        self.__generate_patched_conf(cs)
        self.__create_kbuild(cs)

        # If there are more then one source file, we cannot fully infer what are
        # the correct configs and mods to be livepatched, so leave the mod and
        # config entries empty
        self.__generate_header_file(lp_path, cs)

        # Run the template engine for each touched source file.
        for src_file, _ in files.items():
            self.__generate_lp_file(lp_path, cs, src_file, is_multi_files)

        # One additional file to encapsulate the _init and _clenaup methods
        # of the other source files
        if is_multi_files:
            self.__generate_lp_file(lp_path, cs, None, False)

    # Create Kbuild.inc file adding an entry for all generated livepatch files.
    def __create_kbuild(self, cs):
        render_vars = {"bsc": cs.lp_name, "cs": cs, "lpdir": cs.lpdir()}
        with open(Path(cs.lpdir(), "Kbuild.inc"), "w") as f:
            f.write(Template(TEMPL_KBUILD).render(**render_vars))

    def generate_commit_msg_file(self):
        cmts = self.cs_data.commits.get("upstream", {})
        if cmts:
            cmts = cmts["commits"]
        user, email = get_mail()
        render_vars = {
            "lp_name": self.lp_name.replace("bsc", ""),
            "user": user,
            "email": email,
            "cve": self.cs_data.cve if self.cs_data.cve else "XXXX-XXXX",
            "commits": cmts,
            "msg": "Upstream commits" if len(cmts) > 1 else "Upstream commit",
        }
        with open(Path(self.lp_path, "commit.msg"), "w") as f:
            f.write(Template(TEMPL_COMMIT).render(**render_vars))
