from datetime import datetime
import git
import jinja2
import json
import pathlib
import os
import re
import requests
import textwrap

class Template:
    def __init__(self, bsc, ktype):
        self._bsc = 'bsc' + re.search('([0-9]+)', bsc).group(1)
        conf = pathlib.Path(os.getenv('KLP_WORK_DIR'), self._bsc, 'conf.json')
        if not conf.is_file():
            raise ValueError('config.json not found in {}'.format(str(conf)))

        self._ktype = ktype
        with open(conf, 'r') as f:
            data = json.load(f)
            self._bsc_num = data['bsc']
            self._mod = data['mod']
            self._cve = data['cve']
            self._conf = data['conf']
            self._files = data['files']
            self._commits = data['upstream-commits']
        try:
            conf = git.GitConfigParser()
            self._user = conf.get_value('user', 'name')
            self._email = conf.get_value('user', 'email')
        except:
            raise RuntimeError('Please define name/email in global git config')

        self._env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'), \
                    trim_blocks=True)

    def GenerateLivePatches(self):
        fname = 'kgr_patch' if self._ktype == 'kgr' else 'livepatch'
        fname = fname + '_' + self._bsc

        bsc = pathlib.Path(self._bsc)
        bsc.mkdir(exist_ok=True)

        for ext in ['h', 'c']:
            templ = self._env.get_template('lp-' + ext + '.j2')

            templ.globals['year'] = datetime.today().year

            if self._mod:
                templ.globals['mod'] = self._mod

            lp_file = pathlib.Path(bsc, fname + '.' + ext)
            with open(lp_file, 'w') as f:
                f.write(templ.render(bsc = self._bsc,
                                    bsc_num = self._bsc_num,
                                    cve = self._cve,
                                    config = self._conf,
                                    ktype = self._ktype,
                                    user = self._user,
                                    email = self._email))

        with open(pathlib.Path(bsc, 'patched_funcs.csv'), 'w') as f:
            mod = 'vmlinux' if not self._mod else self._mod
            for file_funcs in self._files.items():
                for func in file_funcs[1]:
                    f.write('{} {} {} IS_ENABLED({})\n'.format(mod, func,
                                                    'klpp_' + func,
                                                    self._conf))


    def _get_commit_subject(self, commit):
        req = requests.get('https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={}'.format(commit))
        req.raise_for_status()

        return re.search('Subject: (.*)', req.text).group(1)

    # Return the commit message in a list of wrapped
    def generate_commit_msg(self):
        commit_list = {}
        for commit in self._commits:
            commit_list[commit] = self._get_commit_subject(commit)

        templ = self._env.get_template('commit.j2')
        msg = templ.render(bsc = self._bsc,
                            bsc_num = self._bsc_num,
                            cve = self._cve,
                            user = self._user,
                            email = self._email,
                            commits = commit_list)

        wrapper = textwrap.TextWrapper(width=80, replace_whitespace=False)
        return '\n'.join(wrapper.wrap(msg))
