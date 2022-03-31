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
    def __init__(self, cfg, cs):
        self.cfg = cfg
        self.bsc = cfg.bsc

        conf = pathlib.Path(cfg.bsc_path, 'conf.json')
        if not conf.is_file():
            raise ValueError('config.json not found in {}'.format(str(conf)))

        codestreams = pathlib.Path(cfg.bsc_path, 'codestreams.json')
        if not codestreams.is_file():
            raise ValueError('codestreams.json not found in {}'.format(str(codestreams)))

        with open(conf, 'r') as f:
            data = json.load(f)
            self._mod = data['mod']
            self._cve = data['cve']
            self._conf = data['conf']
            self._commits = data['commits']

        if cs:
            self._cs = cs
            with open(codestreams, 'r') as f:
                data = json.load(f)
                jcs = data[cs]
                self._ktype = jcs['rename_prefix']
                self._files = list(jcs['files'].keys())

        try:
            conf = git.GitConfigParser()
            self._user = conf.get_value('user', 'name')
            self._email = conf.get_value('user', 'email')
        except:
            raise RuntimeError('Please define name/email in global git config')

        self._templ_path = pathlib.Path(os.path.dirname(__file__), 'templates')
 
    def GenerateLivepatchFile(self, ext, out_name, src_file, ext_file):
        if not out_name and not src_file:
            raise RuntimeError('Both out_name and src_file are empty.  Aborting.')

        if src_file:
            src_file = str(pathlib.Path(src_file).name)

            work_path = pathlib.Path(self.cfg.bsc_path, 'c', self._cs, 'x86_64')

            lp_inc_dir = str(pathlib.Path(work_path, 'work_' + src_file))
            lp_file = self.cfg.bsc + '_' + src_file
        else:
            lp_inc_dir = ''
            lp_file = None

        # out_name empty means that we want the final file as:
        #       bscXXXXXXX_{src_name}.c
        if not out_name:
            out_name = lp_file

        print(lp_inc_dir)

        fsloader = jinja2.FileSystemLoader([self._templ_path, lp_inc_dir])
        env = jinja2.Environment(loader=fsloader, trim_blocks=True)

        templ = env.get_template('lp-' + ext + '.j2')
        templ.globals['year'] = datetime.today().year
        if self._mod:
            templ.globals['mod'] = self._mod

        with open(pathlib.Path(self.cfg.bsc, out_name).with_suffix('.' + ext), 'w') as f:
            f.write(templ.render(bsc = self.cfg.bsc,
                                bsc_num = self.cfg.bsc_num,
                                fname = os.path.splitext(out_name)[0],
                                inc_src_file = lp_file,
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
        bsc = pathlib.Path(self.cfg.bsc)
        bsc.mkdir(exist_ok=True)

        # We need at least one header file for the livepatch
        out_name = 'kgr_patch' if self._ktype == 'kgr' else 'livepatch'
        out_name = out_name + '_' + self.cfg.bsc

        self.GenerateLivepatchFile('h', out_name, None, None)

        if len(self._files) == 1:
            self.GenerateLivepatchFile('c', out_name, self._files[0], 'exts')
            return

        # Run the template engine for each touched source file.
        for src_file in self._files:
            self.GenerateLivepatchFile('c', None, src_file, 'exts')

        # One additional file to encapsulate the _init and _clenaup methods
        # of the other source files
        self.GenerateLivepatchFile('c', out_name, None, None)

    # Return the commit message in a list of wrapped
    def generate_commit_msg(self):
        fsloader = jinja2.FileSystemLoader(self._templ_path)
        self._env = jinja2.Environment(loader=fsloader, trim_blocks=True)

        templ = self._env.get_template('commit.j2')
        return templ.render(bsc = self.cfg.bsc,
                            bsc_num = self.cfg.bsc_num,
                            cve = self._cve,
                            user = self._user,
                            email = self._email,
                            commits = self._commits)
