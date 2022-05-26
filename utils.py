import glob
import json
from pathlib import Path
import re
import requests
import sys

import ccp
from templ import Template
import ksrc

class Setup:
    def __init__(self, cfg, redownload, cve, conf, file_funcs, mod,
            ups_commits, disable_ccp):
        self.cfg = cfg

        self._cve = re.search('([0-9]+\-[0-9]+)', cve).group(1)
        self._kernel_conf = conf

        self._githelper = ksrc.GitHelper(cfg, ups_commits)
        self._mod = mod
        self._redownload = redownload

        self._disable_ccp = disable_ccp
        self._file_funcs = {}

        for f in file_funcs:
            cs = f[0]
            filepath = f[1]
            funcs = f[2:]
            # We can have multiple files per cs being specified, so do not
            # remove previously stored file/funcs pairs
            if not self._file_funcs.get(cs):
                self._file_funcs[cs] = {}

            self._file_funcs[cs][filepath] = funcs

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
        if self.cfg.in_file.exists() and not self._redownload:
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
        file_buf = []
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
            columns = line.decode('utf-8').split(',')
            kernel = re.sub('\.\d+$', '', columns[2])

            sle, sp, u = self.parse_cs_line(columns[0])
            if self.cfg.filter and not re.match(self.cfg.filter, '{}.{}u{}'.format(sle, sp, u)):
                continue

            file_buf.append(columns[0] + ',' + columns[1] + ',' + columns[2] + ',,rpm-' + kernel)

        self.cfg.in_codestreams = '\n'.join(file_buf)
        with open(self.cfg.in_file, 'w') as f:
            f.write(self.cfg.in_codestreams)

    def fill_cs_json(self):
        kernels = []

        for line in self.cfg.in_codestreams.splitlines():
            full_cs, proj, kernel_full, _, _= line.strip().split(',')\

            sle, sp, u = self.parse_cs_line(full_cs)
            cs_key = sle + '.' + sp + 'u' + u

            cs_files = {}

            for cs_regex in self._file_funcs.keys():
                if re.match(cs_regex, cs_key):
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
                print('Kernel {} does not have any file-funcs associated. Skipping'.format(cs_key))
                continue

            ex_dir = self.cfg.get_ex_dir(full_cs)
            if not ex_dir.is_dir():
                print('Codestream not found at {}. Aborting.'.format(str(ex_dir)))
                sys.exit(1)

            kernel = re.sub('\.\d+$', '', kernel_full)

            # do not expect any problems with the kernel release format
            kernels.append(re.search('^([0-9]+\.[0-9]+)', kernel).group(1))

            if not self._mod:
                obj = Path(ex_dir, 'boot', 'vmlinux-' + kernel + '-default')
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
                    if not ksrc.GitHelper.verify_func_object(func, str(obj)):
                        print('WARN: {}: Function {} does not exist in {}.'.format(cs_key, func, obj))

            self.cfg.codestreams[cs_key] = {
                'project' : proj,
                'kernel' : kernel,
                'build-counter' : kernel_full[-1],
                'branch' : '',
                'cs' : full_cs,
                'sle' : sle,
                'sp' : sp,
                'update' : u,
                'readelf' : 'readelf',
                'rename_prefix' : self.get_rename_prefix(cs_key),
                'object' : str(obj),
                'files' : cs_files
            }

        # We create a dict to remove the duplicate kernel versions, used as CVE
        # branches for find the fixes for each codestreams in kernel-source
        # later on
        self._cve_branches = list(dict.fromkeys(kernels))

    def write_json_files(self):
        self.cfg.conf = {
                'bsc' : str(self.cfg.bsc_num),
                'cve' : self._cve,
                'conf' : self._kernel_conf,
                'mod' : self._mod,
                'cve_branches' : self._cve_branches,
                'commits' : self._githelper.commits,
                'patched' : self._githelper.patched,
                'work_dir' : str(self.cfg.bsc_path),
                'data' : str(self.cfg.data)
        }

        with open(self.cfg.conf_file, 'w') as f:
            f.write(json.dumps(self.cfg.conf, indent=4))

        with open(self.cfg.cs_file, 'w') as f:
            f.write(json.dumps(self.cfg.codestreams, indent=4))

    def write_commit_file(self):
        with open(Path(self.cfg.bsc_path, 'commit.msg'), 'w') as f:
            f.write(Template.generate_commit_msg(self.cfg))

    def download_env(self):
        print('FIXME: implement the download and extraction of kernel rpms and ipa-clones')

    def prepare_env(self):
        self.download_codestream_file()

        self.fill_cs_json()

        self._githelper.get_commits(self._cve_branches)
        self._githelper.find_patched(self._cve_branches)

        self.write_json_files()
        self.write_commit_file()

        if not self._disable_ccp:
            _ccp = ccp.CCP(self.cfg)
            _ccp.run_ccp()
