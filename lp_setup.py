from config import Config
import glob
import json
from pathlib import Path
import re
import requests
import sys

from ibs import IBS
from ksrc import GitHelper

class Setup(Config):
    def __init__(self, bsc, bsc_filter, redownload, cve, conf, file_funcs, mod,
            ups_commits, archs):
        super().__init__(bsc, bsc_filter)

        for arch in archs:
            if arch not in ['x86_64', 's390x', 'ppc64le']:
                raise ValueError(f'{arch} is not a valid architecture')

        if self.bsc_path.exists() and not self.bsc_path.is_dir():
            raise ValueError('--bsc needs to be a directory, or not to exist')

        self.conf['mod'] = mod
        self.conf['conf'] = conf
        self.conf['archs'] = archs
        self.conf['cve'] = re.search('([0-9]+\-[0-9]+)', cve).group(1)

        self.ksrc = GitHelper(self.bsc_num, self.filter)

        self._ups_commits = ups_commits
        self._redownload = redownload
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

    # Parse SLE15-SP2_Update_25 to 15.2u25
    def parse_cs_line(self, cs):
        sle, _, u = cs.replace('SLE', '').split('_')
        if '-SP' in sle:
            sle, sp = sle.split('-SP')
        else:
            sle, sp = sle, '0'

        return int(sle), int(sp), int(u)

    def setup_project_files(self):
        if self.cs_file.exists() and not self._redownload:
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
                cs_key = f'{sle}.{sp}u{u}'
                self.codestreams[cs_key] = {
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

        # Called at this point because codestreams is populated
        self.conf['commits'] = self.ksrc.get_commits(self._ups_commits)
        self.conf['patched'] = self.ksrc.get_patched_cs(self.conf['commits'])

        # cpp will use this data in the next step
        with open(self.conf_file, 'w') as f:
            f.write(json.dumps(self.conf, indent=4, sort_keys=True))

        cs_data_missing = []

        filter_out = []

        # Filter by file-funcs
        for cs, data in self.codestreams.items():
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
                filter_out.append(cs)
                continue

            data['files'] = cs_files
            data['repo'] = self.cs_repo(cs)

            # Set supported archs for the codestream
            archs = ['x86_64']
            if self.is_ppc_supported(cs):
                archs.append('ppc64le')

            if self.is_s390_supported(cs):
                archs.append('s390x')

            data['archs'] = archs

            if not self.get_ex_dir(data['cs'], 'x86_64').is_dir():
                cs_data_missing.append(cs)

        # working_cs will contain the final dict of codestreams that wast set
        # by the user, avoid downloading missing codestreams that are not affected
        working_cs = self.filter_cs(check_file_funcs=True, verbose=True)

        # Save codestreams file before something bad can happen
        with open(self.cs_file, 'w') as f:
            f.write(json.dumps(self.codestreams, indent=4, sort_keys=True))

        # Found missing cs data, downloading and extract
        if cs_data_missing:
            print('Download the necessary data from the following codestreams:')
            print(f'\t{" ".join(cs_data_missing)}\n')
            ibs = IBS(self.bsc_num, self.filter)
            ibs.download_cs_data(cs_data_missing)

        # Setup the missing codestream info needed
        for cs, data in working_cs.items():
            print(cs)
            cs_files = data['files']

            # Check if the files exist in the respective codestream directories
            sdir = self.get_sdir(cs)
            for f in cs_files.keys():
                fdir = Path(sdir, f)
                if not fdir.is_file():
                    raise RuntimeError(f'File {f} doesn\'t exists in {str(sdir)}')

            obj = self.get_module_obj(data)

            # Verify if the functions exist in the specified object
            for f in cs_files.keys():
                for func in cs_files[f]:
                    if not self.check_symbol(func, obj):
                        print(f'WARN: {cs}: Function {func} does not exist in {obj}')

            data['object'] = str(obj)

        # Save again to now include object being set.
        # TODO: adapt the code above to be more resilient, so we can rely on
        # saving only at this point.
        with open(self.cs_file, 'w') as f:
            f.write(json.dumps(self.codestreams, indent=4, sort_keys=True))

        # The returned value can be used by ccp
        return working_cs

    def get_module_obj(self, jcs):
        ex_dir = self.get_ex_dir(jcs['cs'], 'x86_64')
        mod = self.conf['mod']
        if mod == 'vmlinux':
            return str(Path(ex_dir, 'boot', f"vmlinux-{jcs['kernel']}-default"))

        obj_path = str(Path(ex_dir, 'lib', 'modules'))
        obj = glob.glob(f'{obj_path}/**/{mod}.ko', recursive=True)

        if not obj or len(obj) > 1:
            print(obj_path)
            raise RuntimeError(f'Module list has none or too much entries: {str(obj)}')

        # Grab the only value of the list and turn obj into a string to be
        # used later
        return str(obj[0])

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
