from datetime import datetime
import jinja2
from mako.template import Template
from pathlib import Path, PurePath
import os

from config import Config

TEMPL_HEADER = '''\
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
'''

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

class TemplateGen(Config):
    def __init__(self, bsc, bsc_filter):
        super().__init__(bsc, bsc_filter)

        # Require the IS_ENABLED ifdef guard whenever we have a livepatch that
        # is not enabled on all architectures
        self.check_enabled = self.conf['archs'] != self.archs

    def get_commits(self, commits, cs):
        ret = []

        if not commits.get(cs, ''):
            ret.append(' *  Not affected')
        else:
            for commit, msg in commits[cs].items():
                if cs == 'upstream':
                    ret.append(f' *  {commit} ("{msg}")')
                elif not msg:
                    ret.append(' *  Not affected')
                else:
                    for m in msg:
                        ret.append(f' *  {m}')

        return '\n'.join(ret)

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

    def get_template(self, cs, src_file, template, inc_dir):
        loaddirs = [Path(os.path.dirname(__file__), 'templates')]
        if inc_dir:
            loaddirs.append(inc_dir)

        fsloader = jinja2.FileSystemLoader(loaddirs)
        env = jinja2.Environment(loader=fsloader, trim_blocks=True)
        templ = env.get_template(template)

        # We don't have a specific codestreams when creating the commit file
        if not cs:
            return templ

        return templ

    def __GenerateLivepatchFile(self, lp_path, cs, ext, src_file, use_src_name=False):
        if src_file:
            lp_inc_dir = str(self.get_work_dir(cs, src_file))
            lp_file = self.lp_out_file(src_file)
            fdata = self.get_cs_files(cs)[str(src_file)]
            mod = self.fix_mod_string(fdata['module'])
            if not self.is_mod(mod):
                mod = ''
            fconf = fdata['conf']
            exts = fdata['ext_symbols']

        else:
            lp_inc_dir = None
            lp_file = None
            mod = ''
            fconf = ''
            exts = false

        # if use_src_name is True, the final file will be:
        #       bscXXXXXXX_{src_name}.c
        # else:
        #       livepatch_bscXXXXXXXX.c
        if use_src_name:
            out_name = lp_file
        else:
            out_name = f'livepatch_{self.bsc}.{ext}'

        fname = Path(out_name).with_suffix('')
        if ext == 'c':
            templ = self.get_template(cs, src_file, 'lp-' + ext + '.j2', lp_inc_dir)

        include_header = False
        if 'livepatch_' in out_name and ext == 'c':
            include_header = True

        # 15.4 onwards we don't have module_mutex, so template generate
        # different code
        sle, sp, _, _ = self.get_cs_tuple(cs)
        mod_mutex = sle < 15 or (sle == 15 and sp < 4)

        render_vars = {
                'commits' : self.conf['commits'],
                'include_header' : include_header,
                'cve' : self.conf['cve'],
                'bsc_num' : self.bsc_num,
                'fname' : str(fname),
                'year' : datetime.today().year,
                'user' : self.user,
                'email' : self.email,
                'get_commits' : self.get_commits,
                'config' : fconf,
                'mod' : mod,
                'mod_mutex' : mod_mutex,
                'check_enabled' : self.check_enabled,
                'inc_exts_file' : ext == 'c' and exts
        }

        with open(Path(lp_path, out_name), 'w') as f:
            if ext == 'c':
                templ.globals['bsc_num'] = self.bsc_num
                templ.globals['config'] = fconf
                if exts:
                    templ.globals['inc_exts_file'] = True
                if mod:
                    templ.globals['mod'] = mod
                if self.check_enabled:
                    templ.globals['check_enabled'] = self.check_enabled
                if mod_mutex:
                    templ.globals['mod_mutex'] = True

                f.write(Template(TEMPL_HEADER).render(**render_vars))
                f.write(templ.render(fname = fname, inc_src_file = lp_file))
            else:
                f.write(Template(TEMPL_H).render(**render_vars))

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
