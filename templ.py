from datetime import datetime
import jinja2
from mako.lookup import TemplateLookup
from mako.template import Template
from pathlib import Path, PurePath
import os

from config import Config

TEMPL_H = '''\
#ifndef _${ fname.upper() }_H
#define _${ fname.upper() }_H

% if check_enabled:
#if IS_ENABLED(${ config })
% endif

int ${ fname }_init(void);
% if mod is UNDEFINED:
void ${ fname }_cleanup(void);
% else:
static inline void ${ fname }_cleanup(void) {}
% endif %

% if check_enabled:
#else /* !IS_ENABLED(${ config }) */
% endif

static inline int ${ fname }_init(void) { return 0; }
static inline void ${ fname }_cleanup(void) {}

% if check_enabled:
#endif /* IS_ENABLED(${ config }) */
% endif

#endif /* _${ fname.upper() }_H */
'''

TEMPL_C = '''\
<%
def get_commits(cmts, cs):
    if not cmts.get(cs, ''):
        return ' *  Not affected'

    ret = []
    for commit, msg in cmts[cs].items():
        if cs == 'upstream':
            ret.append(f' *  {commit} ("{msg}")')
        elif not msg:
            ret.append(' *  Not affected')
        else:
            for m in msg:
                ret.append(f' *  {m}')

    return "\\n".join(ret)
%> \
/*
 * ${fname}
 *
 * Fix for CVE-${cve}, bsc#${bsc_num}
 *
% if include_header:
 *  Upstream commit:
${get_commits(commits, 'upstream')}
 *
 *  SLE12-SP4, SLE12-SP5 and SLE15-SP1 commit:
${get_commits(commits, '4.12')}
 *
 *  SLE15-SP2 and -SP3 commit:
${get_commits(commits, '5.3')}
 *
 *  SLE15-SP4 and -SP5 commit:
${get_commits(commits, 'sle15-sp4')}
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

% if check_enabled:
#if IS_ENABLED(${ config })
% endif # check_enabled

% if mod:
#if !IS_MODULE(${ config })
#error "Live patch supports only CONFIG=m"
#endif
% endif # mod

% if inc_src_file:
<%include file="${ inc_src_file }"/>
% endif # inc_src_file

#include "livepatch_bsc${ bsc_num }.h"
% if hollow_c:
int ${ fname }_init(void)
{
    return 0;
}

void ${ fname }_cleanup(void)
{
}
% else: # hollow_c
% if inc_exts_file:
#include <linux/kernel.h>
% if mod:
#include <linux/module.h>
% endif # mod
#include "../kallsyms_relocs.h"

% if mod:
#define LP_MODULE "${ mod }"
% endif # mod

static struct klp_kallsyms_reloc klp_funcs[] = {
<%include file="exts"/>
};

% if mod:
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
% endif # mod

int ${ fname }_init(void)
{
% if mod:
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
% else: # mod
% if mod_mutex:
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
% else: # mod_mutex
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
% endif # mod_mutex
% endif # mod
}

% if mod:
void ${ fname }_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
% endif # mod
% endif # inc_exts_file
% endif # hollow_c
% if check_enabled:

#endif /* IS_ENABLED(${ config }) */
% endif check_enabled
'''

class TemplateGen(Config):
    def __init__(self, bsc, bsc_filter):
        super().__init__(bsc, bsc_filter)

        # Require the IS_ENABLED ifdef guard whenever we have a livepatch that
        # is not enabled on all architectures
        self.check_enabled = self.conf['archs'] != self.archs

    def fix_mod_string(self, mod):
        # Modules like snd-pcm needs to be replaced by snd_pcm in LP_MODULE
        # and in kallsyms lookup
        return mod.replace('-', '_')

    def GeneratePatchedFuncs(self, lp_path, cs_files):
        with open(Path(lp_path, 'patched_funcs.csv'), 'w') as f:
            for ffile, fdata in cs_files.items():
                conf = fdata['conf']
                if conf and self.check_enabled:
                    conf = f' IS_ENABLED({conf})'
                else:
                    conf = ''

                mod = self.fix_mod_string(fdata['module'])
                for func in fdata['symbols']:
                    f.write(f'{mod} {func} klpp_{func}{conf}\n')

    def __GenerateLivepatchFile(self, lp_path, cs, ext, src_file, use_src_name=False):
        if src_file:
            lp_inc_dir = str(self.get_work_dir(cs, src_file))
            lp_file = self.lp_out_file(src_file)
            fdata = self.get_cs_files(cs)[str(src_file)]
            mod = self.fix_mod_string(fdata['module'])
            if not self.is_mod(mod):
                mod = ''
            fconf = fdata['conf']

        else:
            lp_inc_dir = Path('non-existent')
            lp_file = None
            mod = ''
            fconf = ''

        exts = Path(lp_inc_dir, 'exts')

        # if use_src_name is True, the final file will be:
        #       bscXXXXXXX_{src_name}.c
        # else:
        #       livepatch_bscXXXXXXXX.c
        if use_src_name:
            out_name = lp_file
        else:
            out_name = f'livepatch_{self.bsc}.{ext}'

        # 15.4 onwards we don't have module_mutex, so template generate
        # different code
        sle, sp, _, _ = self.get_cs_tuple(cs)
        mod_mutex = sle < 15 or (sle == 15 and sp < 4)

        render_vars = {
                'commits' : self.conf['commits'],
                'include_header' : 'livepatch_' in out_name and ext == 'c',
                'cve' : self.conf['cve'],
                'bsc_num' : self.bsc_num,
                'fname' : str(Path(out_name).with_suffix('')),
                'year' : datetime.today().year,
                'user' : self.user,
                'email' : self.email,
                'config' : fconf,
                'mod' : mod,
                'mod_mutex' : mod_mutex,
                'check_enabled' : self.check_enabled,
                'inc_exts_file' : exts.exists(),
                'inc_src_file' : lp_file,
                'hollow_c' : ext == 'c' and not src_file
        }

        with open(Path(lp_path, out_name), 'w') as f:
            lpdir = TemplateLookup(directories=[lp_inc_dir])
            temp_str = TEMPL_H
            if ext == 'c':
                temp_str = TEMPL_C

            f.write(Template(temp_str, lookup=lpdir).render(**render_vars))

    def GenerateLivePatches(self, cs):
        lp_path = self.get_cs_lp_dir(cs)
        lp_path.mkdir(exist_ok=True)

        files = self.get_cs_files(cs)
        self.GeneratePatchedFuncs(lp_path, files)

        # If the livepatch touches only one file the final livepatch file will
        # be names livepatch_XXXX
        if len(files.keys()) == 1:
            src = Path(list(files.keys())[0])
            self.__GenerateLivepatchFile(lp_path, cs, 'c', src)
            self.__GenerateLivepatchFile(lp_path, cs, 'h', src)
            return

        # If there are more then one source file, we cannot fully infer what are
        # the correct configs and mods to be livepatched, so leave the mod and
        # config entries empty
        self.__GenerateLivepatchFile(lp_path, cs, 'h', None)

        # Run the template engine for each touched source file.
        for src_file, _ in files.items():
            self.__GenerateLivepatchFile(lp_path, cs, 'c', src_file, True)

        # One additional file to encapsulate the _init and _clenaup methods
        # of the other source files
        self.__GenerateLivepatchFile(lp_path, cs, 'c', None)

    # Create Kbuild.inc file adding an entry for all geenerated livepatch files.
    def CreateKbuildFile(self, cs):
        cs_, sp, u, _ = self.get_cs_tuple(cs)
        bscn = self.conf['bsc']
        lp_dir = self.get_cs_lp_dir(cs)

        with open(Path(lp_dir, 'Kbuild.inc'), 'w') as f:
            for entry in lp_dir.iterdir():
                fname = entry.name
                if not fname.endswith('.c'):
                    continue

                fname = PurePath(fname).with_suffix('.o')

                # For kernels 5.4 and beyond Kbuild uses relative path to add
                # CFLAGS to objects
                if cs_ > 15 or (cs_ == 15 and sp >= 4):
                    fname = f'bsc{bscn}/{fname}'

                f.write(f'CFLAGS_{fname} += -Werror\n')

    def generate_commit_msg_file(self):
        with open(Path(self.bsc_path, 'commit.msg'), 'w') as f:
            commits = self.conf['commits'].get('upstream', {})
            commit_str = 'Upstream commit'
            # add plural when necessary
            if len(commits) > 1:
                commit_str = commit_str + 's'

            cve = self.conf['cve']
            print(f'Fix for CVE-{cve} ("CHANGE ME!")', '',
                f'Live patch for CVE-{cve}. {commit_str}:', sep='\n',
                  file=f)

            for commit_hash, msg in commits.items():
                print(f'- {commit_hash} ("{msg}")', file=f)

            print('', f'KLP: CVE-{cve}', f'References: bsc#{self.bsc_num} CVE-{cve}',
                    f'Signed-off-by: {self.user} <{self.email}>', sep='\n',
                  file=f)
