import glob
import json
from pathlib import Path
import re
import requests
import sys

import ccp
from templ import Template
from ksrc import GitHelper

class Setup:
    def __init__(self, cfg, redownload, cve, conf, file_funcs, mod,
            ups_commits, disable_ccp):
        self.cfg = cfg

        self._cve = re.search('([0-9]+\-[0-9]+)', cve).group(1)
        self._kernel_conf = conf

        self._ups_commits = ups_commits
        self._mod = mod
        self._redownload = redownload

        self._disable_ccp = disable_ccp
        self._file_funcs = {}

        self.commits = []
        self.patched = []

        for f in file_funcs:
            cs = f[0]
            filepath = f[1]
            funcs = f[2:]
            # We can have multiple files per cs being specified, so do not
            # remove previously stored file/funcs pairs
            if not self._file_funcs.get(cs):
                self._file_funcs[cs] = {}

            self._file_funcs[cs][filepath] = funcs

    # Parse SLE15-SP2_Update_25 to 15.2u25
    def parse_cs_line(self, cs):
        sle, _, u = cs.replace('SLE', '').split('_')
        if '-SP' in sle:
            sle, sp = sle.split('-SP')
        else:
            sle, sp = sle, '0'

        return sle, sp, u

    def setup_project_files(self):
        if self.cfg.cs_file.exists() and not self._redownload:
            print('Found codestreams.json file, loading downloaded file.')
        else:
            print('Downloading codestreams file')
            req = requests.get('https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv')

            # exit on error
            req.raise_for_status()

            first_line = True
            for line in req.iter_lines():
                # skip empty lines
                if not line:
                    continue

                # skip file header
                if first_line:
                    first_line = False
                    continue

                # remove the last two columns, which are dates of the line
                # and add a fifth field with the forth one + rpm- prefix, and
                # remove the build counter number
                full_cs, proj, kernel_full, _, _= line.decode('utf-8').strip().split(',')
                kernel = re.sub('\.\d+$', '', kernel_full)

                # Fill the majority of possible fields here
                sle, sp, u = self.parse_cs_line(full_cs)
                cs_key = sle + '.' + sp + 'u' + u
                self.cfg.codestreams[cs_key] = {
                        'project' : proj,
                        'kernel' : kernel,
                        'build-counter' : kernel_full[-1],
                        'branch' : '',
                        'cs' : full_cs,
                        'sle' : sle,
                        'sp' : sp,
                        'update' : u,
                        'readelf' : 'readelf'
                }

        print('Validating codestreams data...')
        # For now let's keep the current format of codestreams.in and
        # codestreams.json
        if self.cfg.filter:
            print('Applying filter...')

        skip_cs = []
        for cs in self.cfg.codestreams.keys():
            jcs = self.cfg.codestreams[cs]

            if self.cfg.filter and not re.match(self.cfg.filter, cs):
                skip_cs.append(cs)
                continue

            ex_dir = self.cfg.get_ex_dir(jcs['cs'])
            if not ex_dir.is_dir():
                print('Data related to codestream {} not found.  Downloading...'.format(cs))
                GitHelper.download_cs_data(self.cfg, jcs['cs'], jcs['project'])

            cs_files = {}
            for cs_regex in self._file_funcs.keys():
                if re.match(cs_regex, cs):
                    # Convert dict to tuples
                    for k, v in list(self._file_funcs[cs_regex].items()):
                        # At this point we can have multiple regexes to specify
                        # different functions per file per codestream. In this case,
                        # we need to append the new functions to a file that can be
                        # added in a previous iteration.

                        # Copy the list here to avoid changing the _file_funcs
                        values = v.copy()
                        if cs_files.get(k, []):
                            values.extend(cs_files[k])
                        cs_files[k] = values

            if not cs_files:
                print('Kernel {} does not have any file-funcs associated. Skipping'.format(cs))
                skip_cs.append(cs)
                continue

            # Check if the files exist in the respective codestream directories
            sdir = Path(self.cfg.ex_dir, jcs['cs'], 'usr', 'src', 'linux-' + jcs['kernel'])
            for f in cs_files.keys():
                fdir = Path(sdir, f)
                if not fdir.is_file():
                    raise RuntimeError('File {} doesn\'t exists in {}'.format(f,
                        str(sdir)))

            jcs['files'] = cs_files

            if not self._mod:
                obj = Path(ex_dir, 'boot', 'vmlinux-' + jcs['kernel'] + '-default')
            else:
                mod_file = self._mod + '.ko'
                obj_path = Path(ex_dir, 'lib', 'modules')
                obj = glob.glob(str(obj_path) + '/**/' + mod_file, recursive=True)

                if not obj or len(obj) > 1:
                    print(line)
                    raise RuntimeError('Module list has none or too much entries: ' + str(obj))
                # Grab the only value of the list and turn obj into a string to be
                # used later
                obj = obj[0]

            # Verify if the functions exist in the specified object
            for f in cs_files.keys():
                for func in cs_files[f]:
                    if not GitHelper.verify_func_object(func, str(obj)):
                        print('WARN: {}: Function {} does not exist in {}.'.format(cs, func, obj))

            jcs['object'] = str(obj)

        # Removing filtered/skipped codestreams
        for cs in skip_cs:
            del self.cfg.codestreams[cs]

        with open(self.cfg.cs_file, 'w') as f:
            f.write(json.dumps(self.cfg.codestreams, indent=4))

        # set cfg.conf so ccp can use it later
        self.cfg.conf = {
                'bsc' : str(self.cfg.bsc_num),
                'cve' : self._cve,
                'conf' : self._kernel_conf,
                'mod' : self._mod,
                'commits' : self.commits,
                'patched' : self.patched,
                'work_dir' : str(self.cfg.bsc_path),
                'data' : str(self.cfg.data)
        }

        with open(self.cfg.conf_file, 'w') as f:
            f.write(json.dumps(self.cfg.conf, indent=4))

    def download_env(self):
        print('FIXME: implement the download and extraction of kernel rpms and ipa-clones')

    def prepare_env(self):
        self.commits = GitHelper.get_commits(self.cfg, self._ups_commits)
        self.patched = GitHelper.get_patched_cs(self.cfg, self.commits)

        self.setup_project_files()

        Template.generate_commit_msg_file(self.cfg)

        if not self._disable_ccp:
            _ccp = ccp.CCP(self.cfg)
            _ccp.run_ccp()
