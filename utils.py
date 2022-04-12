import glob
import json
import pathlib
from pathlib import Path
import os
import re
import requests
import subprocess

import templ
import ksrc

class Setup:
    _cs_file = None
    _cs_json = {}
    _cve_branches = []

    def __init__(self, cfg, redownload, cve, conf, file_funcs, mod,
            ups_commits):
        self.cfg = cfg
        self.cfg.bsc_path.mkdir(exist_ok=True)

        self._cve = re.search('([0-9]+\-[0-9]+)', cve).group(1)
        self._conf = conf
        self._file_funcs = file_funcs
        self._commits = { 'upstream' : {} }
        for commit in ups_commits:
            commit = commit[:12]
            self._commits['upstream'][commit] = self.get_commit_subject(commit)

        self._mod = mod

        self._redownload = redownload

        self._rpm_dir = pathlib.Path(cfg.env, 'kernel-rpms')
        self._ex_dir = pathlib.Path(cfg.env, 'ex-kernels')
        self._ipa_dir = pathlib.Path(cfg.env, 'ipa-clones')

    def get_rename_prefix(self, cs):
        if '12.3' in cs:
            return 'kgr'
        return 'klp'

    # Parse SLE15-SP2_Update_25 to 15.2u25
    def parse_cs_line(self, cs):
        sle, _, u = cs.replace('SLE', '').split('_')
        if '-SP' in sle:
            sle, sp = sle.split('-SP')
        else:
            sle, sp = sle, '0'

        return sle, sp, u

    def download_codestream_file(self):
        self._cs_file = pathlib.Path(self.cfg.bsc_path, 'codestreams.in')

        if os.path.isfile(self._cs_file) and not self._redownload:
            print('Found codestreams.in file, skipping download.')
            return

        req = requests.get('https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv')

        # exit on error
        req.raise_for_status()

        # For now let's keep the current format of codestreams.in and
        # codestreams.json

        if self.cfg.filter:
            print('Applying filter...')

        first_line = True
        with open(self._cs_file, 'w') as f:
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
                # remove the micro version number
                columns = line.decode('utf-8').split(',')
                kernel = re.sub('\.\d+$', '', columns[2])

                sle, sp, u = self.parse_cs_line(columns[0])
                if self.cfg.filter and not re.match(self.cfg.filter, '{}.{}u{}'.format(sle, sp, u)):
                    print('Skipping {}'.format(columns[0]))
                    continue

                f.write(columns[0] + ',' + columns[1] + ',' + columns[2] + ',,rpm-' + kernel + '\n')

    def fill_cs_json(self):
        if not self._ex_dir.is_dir() or not self._ipa_dir.is_dir():
            raise RuntimeError('KLP_DATA_DIR was not defined, or ex-kernel/ipa-clones does not exist')

        files = {}
        for f in self._file_funcs:
            cs = f[0]
            filepath = f[1]
            funcs = f[2:]
            if not files.get(cs, {}):
                files[cs] = {}
            files[cs][filepath] = funcs

        kernels = []
        with open(self._cs_file, 'r') as f:
            for line in f:
                full_cs, proj, kernel_full, _, _= line.strip().split(',')

                ex_dir = pathlib.Path(self._ex_dir, full_cs)
                src = pathlib.Path(ex_dir, 'usr', 'src')

                kernel = re.sub('\.\d+$', '', kernel_full)

                # do not expect any problems with the kernel release format
                cs_kernel = re.search('^([0-9]+\.[0-9]+)', kernel).group(1)

                kernels.append(cs_kernel)

                cs_files = files.get(cs_kernel, {})
                if not cs_files:
                    cs_files = files.get('all', {})
                    if not cs_files:
                        print('Kernel {} does not have any file-funcs associated. Skipping'.format(cs_kernel))
                        continue


                if not self._mod:
                    obj = pathlib.Path(ex_dir, 'x86_64', 'boot', 'vmlinux-' +
                            kernel.replace('linux-', '') + '-default')
                else:
                    mod_file = self._mod + '.ko'
                    obj_path = pathlib.Path(ex_dir, 'x86_64', 'lib', 'modules')
                    obj = glob.glob(str(obj_path) + '/**/' + mod_file, recursive=True)

                    if not obj or len(obj) > 1:
                        raise RuntimeError('Module list has none or too much entries: ' + str(obj))
                    # Grab the only value of the list and turn obj into a string to be
                    # used later
                    obj = obj[0]

                sle, sp, u = self.parse_cs_line(full_cs)
                cs_key = sle + '.' + sp + 'u' + u

                self._cs_json[cs_key] = {
                    'project' : proj,
                    'kernel' : kernel,
                    'micro-version' : kernel_full[-1],
                    'branch' : '',
                    'cs' : full_cs,
                    'sle' : sle,
                    'sp' : sp,
                    'update' : u,
                    'readelf' : 'readelf',
                    'rename_prefix' : self.get_rename_prefix(cs),
                    'object' : str(obj),
                    'files' : cs_files
                }

        # We create a dict to remove the duplicate kernel versions, used as CVE
        # branches for find the fixes for each codestreams in kernel-source
        # later on
        self._cve_branches = list(dict.fromkeys(kernels))

    def get_commit_subject(self, commit):
        req = requests.get('https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={}'.format(commit))
        req.raise_for_status()

        patches = Path(self.cfg.bsc_path, 'patches')
        patches.mkdir(exist_ok=True)

        # Save the upstream commit in the bsc directory
        fpath = Path(patches, commit + '.patch')
        with open(fpath, 'w') as f:
            f.write(req.text)

        return re.search('Subject: (.*)', req.text).group(1)

    def write_json_files(self):
        data = { 'bsc' : str(self.cfg.bsc_num),
                'cve' : self._cve,
                'conf' : self._conf,
                'mod' : self._mod,
                'cve_branches' : self._cve_branches,
                'commits' : self._commits,
                'ex_kernels' : str(self._ex_dir),
                'ipa_clones' : str(self._ipa_dir),
                'work_dir' : str(self.cfg.bsc_path)
        }

        with open(pathlib.Path(self.cfg.bsc_path, 'conf.json'), 'w') as f:
            f.write(json.dumps(data, indent=4))

        with open(pathlib.Path(self.cfg.bsc_path, 'codestreams.json'), 'w') as f:
            f.write(json.dumps(self._cs_json, indent=4))

    def write_commit_file(self):
        temp = templ.Template(self.cfg, None)
        msg = temp.generate_commit_msg()

        with open(pathlib.Path(self.cfg.bsc_path, 'commit.msg'), 'w') as f:
            f.write(msg)

    def download_env(self):
        print('FIXME: implement the download and extraction of kernel rpms and ipa-clones')

    def prepare_env(self):
        self.download_codestream_file()

        self.fill_cs_json()

        githelper = ksrc.GitHelper(self.cfg)
        githelper.get_commits(self._cve_branches, self._commits)

        self.write_json_files()
        self.write_commit_file()
