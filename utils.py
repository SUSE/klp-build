import glob
import json
from pathlib import Path
import re
import requests
import sys

import ccp
from ibs import IBS
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

        self.ibs = None

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

        cs_data_missing = []

        for cs in self.cfg.codestreams.keys():
            jcs = self.cfg.codestreams[cs]
            cs_files = {}

            if self.cfg.filter and not re.match(self.cfg.filter, cs):
                continue

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
                continue

            jcs['files'] = cs_files
            jcs['repo'] = self.cs_repo(jcs)

            # Set supported archs for the codestream
            archs = ['x86_64']
            if self.is_ppc_supported(int(jcs['sle']), int(jcs['sp']),
                                     int(jcs['update'])):
                archs.extend(['ppc64le'])

            if self.is_s390_supported(int(jcs['sle']), int(jcs['sp']),
                                     int(jcs['update'])):
                archs.extend(['s390x'])

            jcs['archs'] = archs

            ex_dir = self.cfg.get_ex_dir(jcs['cs'])
            if not ex_dir.is_dir():
                cs_data_missing.append(cs)

            self.cfg.working_cs.append(cs)

        skip_cs = set(self.cfg.codestreams.keys()) - set(self.cfg.working_cs)
        if skip_cs:
            print('Skipping codestreams:')
            print(f'\t{" ".join(skip_cs)}')

        # Save codestreams file before something bad can happen
        with open(self.cfg.cs_file, 'w') as f:
            f.write(json.dumps(self.cfg.codestreams, indent=4, sort_keys=True))

        # Found missing cs data, downloading and extract
        if cs_data_missing:
            print('Download the necessary data from the following codestreams:')
            print('\t{}'.format(' '.join(cs_data_missing)))
            ibs = IBS(self.cfg)
            ibs.download_cs_data(cs_data_missing)

        # Setup the missing codestream info needed
        for cs in self.cfg.working_cs:
            jcs = self.cfg.codestreams[cs]
            cs_files = jcs['files']

            # Check if the files exist in the respective codestream directories
            sdir = Path(self.cfg.ex_dir, jcs['cs'], 'usr', 'src', f"linux-{jcs['kernel']}")
            for f in cs_files.keys():
                fdir = Path(sdir, f)
                if not fdir.is_file():
                    raise RuntimeError(f'File {f} doesn\'t exists in {str(sdir)}')

            ex_dir = self.cfg.get_ex_dir(jcs['cs'])
            if not self._mod:
                obj = Path(ex_dir, 'boot', f"vmlinux-{jcs['kernel']}-default")
            else:
                mod_file = self._mod + '.ko'
                obj_path = Path(ex_dir, 'lib', 'modules')
                obj = glob.glob(str(obj_path) + '/**/' + mod_file, recursive=True)

                if not obj or len(obj) > 1:
                    print(obj_path)
                    raise RuntimeError(f'Module list has none or too much entries: {str(obj)}')
                # Grab the only value of the list and turn obj into a string to be
                # used later
                obj = obj[0]

            # Verify if the functions exist in the specified object
            for f in cs_files.keys():
                for func in cs_files[f]:
                    if not GitHelper.verify_func_object(func, str(obj)):
                        print(f'WARN: {cs}: Function {func} does not exist in {obj}.')

            jcs['object'] = str(obj)

        # Save again to now include object being set.
        # TODO: adapt the code above to be more resilient, so we can rely on
        # saving only at this point.
        with open(self.cfg.cs_file, 'w') as f:
            f.write(json.dumps(self.cfg.codestreams, indent=4, sort_keys=True))

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
            f.write(json.dumps(self.cfg.conf, indent=4, sort_keys=True))

    def cs_repo(self, jcs):
        if jcs['update'] == "0":
            return 'standard'

        repo = f"SUSE_SLE-{jcs['sle']}"
        if jcs['sp'] != '0':
            repo = f"{repo}-SP{jcs['sp']}"

        return f'{repo}_Update'

    # s390x shall be enabled from SLE12-SP4 update 13 onwards.
    # s390x is supported from 12.5u3 onwards
    # s390x is supported from SLE15-SP2 onwards.
    def is_s390_supported(self, sle, sp, up):
        if (sle == 12 and sp == 4 and up >= 13) or \
                (sle == 12 and sp == 5 and up >= 3) or \
                (sle == 15 and sp >= 2):
            return True

        return False

    # ppc64le is supported from 12_3u5 onwards
    # ppc64le is also supported on 12sp2 from u25 onwards
    def is_ppc_supported(self, sle, sp, up):
        if sle > 12:
            return True
        elif sle == 12 and sp > 3:
            return True
        elif (sle == 12 and sp == 2 and up >= 25) or \
                (sle == 12 and sp == 3 and up >= 5):
           return True

        return False

    def prepare_env(self):
        self.commits = GitHelper.get_commits(self.cfg, self._ups_commits)
        self.patched = GitHelper.get_patched_cs(self.cfg, self.commits)

        self.setup_project_files()

        Template.generate_commit_msg_file(self.cfg)

        if not self._disable_ccp:
            _ccp = ccp.CCP(self.cfg)
            _ccp.run_ccp()
