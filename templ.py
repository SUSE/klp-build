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
    def __init__(self, bsc, work_dir, cs):
        self._bsc = 'bsc' + str(bsc)
        conf = pathlib.Path(work_dir, self._bsc, 'conf.json')
        if not conf.is_file():
            raise ValueError('config.json not found in {}'.format(str(conf)))

        codestreams = pathlib.Path(work_dir, self._bsc, 'codestreams.json')
        if not codestreams.is_file():
            raise ValueError('codestreams.json not found in {}'.format(str(codestreams)))

        with open(conf, 'r') as f:
            data = json.load(f)
            self._bsc_num = data['bsc']
            self._mod = data['mod']
            self._cve = data['cve']
            self._conf = data['conf']
            self._commits = data['commits']

        if cs:
            with open(codestreams, 'r') as f:
                data = json.load(f)
                print(cs)
                jcs = data[cs]
                self._ktype = jcs['rename_prefix']
                self._files = list(jcs['files'].keys())
                self._work_dirs = jcs['work_dir']

        try:
            conf = git.GitConfigParser()
            self._user = conf.get_value('user', 'name')
            self._email = conf.get_value('user', 'email')
        except:
            raise RuntimeError('Please define name/email in global git config')

        self._templ_path = pathlib.Path(os.path.dirname(__file__), 'templates')
 
    def GenerateLivepatchFile(self, ext, fname, file_path, src_file, ext_file):
        fsloader = jinja2.FileSystemLoader([self._templ_path, file_path])
        env = jinja2.Environment(loader=fsloader, trim_blocks=True)

        templ = env.get_template('lp-' + ext + '.j2')
        templ.globals['year'] = datetime.today().year
        if self._mod:
            templ.globals['mod'] = self._mod

        with open(pathlib.Path(self._bsc, fname), 'w') as f:
            f.write(templ.render(bsc = self._bsc,
                                bsc_num = self._bsc_num,
                                inc_src_file = src_file,
                                inc_exts_file = ext_file,
                                cve = self._cve,
                                config = self._conf,
                                ktype = self._ktype,
                                user = self._user,
                                email = self._email,
                                commits = self._commits))

    def GenerateLivePatches(self):
        # If the livepatch contains only one file, generate only the livepatch
        # one
        bsc = pathlib.Path(self._bsc)
        bsc.mkdir(exist_ok=True)

        # We need at least one header file for the livepatch
        fname = 'kgr_patch' if self._ktype == 'kgr' else 'livepatch'
        fname = fname + '_' + self._bsc

        self.GenerateLivepatchFile('h', fname + '.h', '', None, None)

        # Run the template engine for each touched source file.
        for index, wdir in enumerate(self._work_dirs):
            src_name = self._bsc + '_' + pathlib.Path(self._files[index]).name

            # If the livepatch touches only one source file, generate only a
            # 'livepatch_' file, including the touched source file
            _fname = src_name
            if len(self._work_dirs) == 1:
                _fname = fname + '.c'

            self.GenerateLivepatchFile('c', _fname, wdir, src_name, 'exts')

        # One additional file to encapsulate the _init and _clenaup methods
        # of the other source files
        if len(self._work_dirs) > 1:
            self.GenerateLivepatchFile('c', fname + '.c', '', None, None)

    # Return the commit message in a list of wrapped
    def generate_commit_msg(self):
        fsloader = jinja2.FileSystemLoader(self._templ_path)
        self._env = jinja2.Environment(loader=fsloader, trim_blocks=True)

        templ = self._env.get_template('commit.j2')
        return templ.render(bsc = self._bsc,
                            bsc_num = self._bsc_num,
                            cve = self._cve,
                            user = self._user,
                            email = self._email,
                            commits = self._commits)
