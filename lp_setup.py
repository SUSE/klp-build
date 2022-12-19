from config import Config
import json
from pathlib import Path
import re
import requests
import sys

from ibs import IBS
from ksrc import GitHelper

class Setup(Config):
    def __init__(self, bsc, bsc_filter, cve, conf, cs_arg, file_funcs, mod,
            ups_commits, archs):
        super().__init__(bsc, bsc_filter)

        for arch in archs:
            if arch not in self.archs:
                raise ValueError(f'{arch} is not a valid architecture')

        if self.bsc_path.exists() and not self.bsc_path.is_dir():
            raise ValueError('--bsc needs to be a directory, or not to exist')

        self.bsc_path.mkdir(exist_ok=True)

        self.conf['mod'] = mod
        self.conf['conf'] = conf
        self.conf['archs'] = archs
        self.conf['cve'] = re.search('([0-9]+\-[0-9]+)', cve).group(1)

        self.ksrc = GitHelper(self.bsc_num, self.filter)

        self.codestream = cs_arg
        self._ups_commits = ups_commits
        self.file_funcs = {}

        for f in file_funcs:
            filepath = f[0]
            funcs = f[1:]
            self.file_funcs[filepath] = funcs

    # Parse SLE15-SP2_Update_25 to 15.2u25
    def parse_cs_line(self, cs):
        sle, _, u = cs.replace('SLE', '').split('_')
        if '-SP' in sle:
            sle, sp = sle.split('-SP')
        else:
            sle, sp = sle, '0'

        return int(sle), int(sp), int(u)

    def download_supported_file(self):
        print('Downloading codestreams file')
        req = requests.get('https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv')

        # exit on error
        req.raise_for_status()

        first_line = True
        codestreams = {}
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
            cs_key = f'{sle}.{sp}u{u}'
            codestreams[cs_key] = {
                    'project' : proj,
                    'kernel' : kernel,
                    'build-counter' : kernel_full[-1],
                    'branch' : '',
                    'sle' : sle,
                    'sp' : sp,
                    'update' : u
            }

        return codestreams

    def setup_project_files(self):
        # Always get the latest supported.csv file and check the content
        # against the codestreams informed by the user
        all_codestreams = self.download_supported_file()

        # Called at this point because codestreams is populated
        self.conf['commits'] = self.ksrc.get_commits(self._ups_commits)
        self.conf['patched'] = self.ksrc.get_patched_cs(self.conf['commits'])

        # cpp will use this data in the next step
        with open(self.conf_file, 'w') as f:
            f.write(json.dumps(self.conf, indent=4, sort_keys=True))

        cs_data_missing = {}

        # list of codestreams that matches the file-funcs argument
        working_cs = {}

        for cs, data in all_codestreams.items():
            # Only process codestreams that are related to the argument
            if not re.match(self.codestream, cs):
                continue

            # Skip patched codestreams
            if cs in self.conf['patched']:
                continue

            data['files'] = self.file_funcs
            data['repo'] = self.cs_repo(cs)

            # The ext_symbols will be populated by ccp
            for file in self.file_funcs.keys():
                data['ext_symbols'] = { file : [] }

            # Set supported archs for the codestream
            archs = ['x86_64']
            if self.is_ppc_supported(cs):
                archs.append('ppc64le')

            if self.is_s390_supported(cs):
                archs.append('s390x')

            data['archs'] = archs

            if not self.get_data_dir(cs, 'x86_64').is_dir():
                cs_data_missing[cs] = data

            working_cs[cs] = data

        # working_cs will contain the final dict of codestreams that wast set
        # by the user, avoid downloading missing codestreams that are not affected
        self.working_cs = self.filter_cs(working_cs, verbose=True)

        # Remove filtered codestreams from missing data codestreams, as we don't
        # need to download data from codestreams that we don't need to build
        # livepatched
        data_missing = cs_data_missing.copy()
        for cs in cs_data_missing.keys():
            if cs not in self.working_cs.keys():
                data_missing.pop(cs)

        # Found missing cs data, downloading and extract
        if data_missing:
            print('Download the necessary data from the following codestreams:')
            print(f'\t{" ".join(data_missing.keys())}\n')
            ibs = IBS(self.bsc_num, self.filter, self.working_cs)
            ibs.download_cs_data(data_missing)

        print('Validating codestreams data...')

        # Setup the missing codestream info needed
        for cs, data in self.working_cs.items():
            cs_files = data['files']

            # Check if the files exist in the respective codestream directories
            sdir = self.get_sdir(cs)
            for f in cs_files.keys():
                fdir = Path(sdir, f)
                if not fdir.is_file():
                    raise RuntimeError(f'File {f} doesn\'t exists in {str(sdir)}')

            mod = self.conf['mod']
            arch = 'x86_64'
            obj = self.find_module_obj(arch, cs, mod)
            data['object'] = obj

            # Verify if the functions exist in the specified object
            for f in cs_files.keys():
                for func in cs_files[f]:
                    if not self.check_symbol(arch, cs, func, mod):
                        print(f'WARN: {cs}: Function {func} does not exist in {obj}')

        # Update and save codestreams data
        for cs, data in self.working_cs.items():
            self.codestreams[cs] = data

        self.flush_cs_file()

    def cs_repo(self, cs):
        sle, sp, up = self.get_cs_tuple(cs)
        if up == 0:
            return 'standard'

        repo = f"SUSE_SLE-{sle}"
        if sp != 0:
            repo = f"{repo}-SP{sp}"

        return f'{repo}_Update'

    # s390x shall be enabled from SLE12-SP4 update 13 onwards.
    # s390x is supported from 12.5u3 onwards
    # s390x is supported from SLE15-SP2 onwards.
    def is_s390_supported(self, cs):
        sle, sp, up = self.get_cs_tuple(cs)
        if (sle == 12 and sp == 4 and up >= 13) or \
                (sle == 12 and sp == 5 and up >= 3) or \
                (sle == 15 and sp >= 2):
            return True

        return False

    # ppc64le is supported from 12_3u5 onwards
    # ppc64le is also supported on 12sp2 from u25 onwards
    def is_ppc_supported(self, cs):
        sle, sp, up = self.get_cs_tuple(cs)
        if sle > 12:
            return True
        elif sle == 12 and sp > 3:
            return True
        elif (sle == 12 and sp == 2 and up >= 25) or \
                (sle == 12 and sp == 3 and up >= 5):
           return True

        return False
