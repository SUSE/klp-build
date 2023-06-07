from config import Config
import json
from natsort import natsorted
from pathlib import Path
import re
import requests
import sys

from ibs import IBS
from ksrc import GitHelper

class Setup(Config):
    def __init__(self, bsc, bsc_filter, cve, cs_arg,
                 file_funcs, mod_file_funcs, conf_mod_file_funcs,
                 mod_arg, conf, archs):
        super().__init__(bsc, bsc_filter)

        archs.sort()

        # Check if the livepatch isn't enabled on some architectures, and so
        # require conf to be set, otherwise it can be a problem later
        if archs != self.archs and not conf:
            raise ValueError('Please specify --conf when not all architectures are supported')

        if self.is_mod(mod_arg) and not conf:
            raise ValueError('Please specify --conf when a module is specified')

        if self.bsc_path.exists() and not self.bsc_path.is_dir():
            raise ValueError('--bsc needs to be a directory, or not to exist')

        if not file_funcs and not mod_file_funcs and not conf_mod_file_funcs:
            raise ValueError('You need to specify at least one of the file-funcs variants!')

        self.bsc_path.mkdir(exist_ok=True)

        self.conf['archs'] = archs
        self.conf['cve'] = re.search('([0-9]+\-[0-9]+)', cve).group(1)

        self.ksrc = GitHelper(self.bsc_num, self.filter)

        self.codestream = cs_arg
        self.file_funcs = {}

        for f in file_funcs:
            filepath = f[0]
            funcs = f[1:]

            self.file_funcs[filepath] = {
                    'module' : mod_arg,
                    'conf' : conf,
                    'symbols' : funcs
            }

        for f in mod_file_funcs:
            fmod = f[0]
            filepath = f[1]
            funcs = f[2:]

            self.file_funcs[filepath] = {
                    'module' : fmod,
                    'conf' : conf,
                    'symbols' : funcs
            }

        for f in conf_mod_file_funcs:
            fconf = f[0]
            fmod = f[1]
            filepath = f[2]
            funcs = f[3:]

            self.file_funcs[filepath] = {
                    'module' : fmod,
                    'conf' : fconf,
                    'symbols' : funcs
            }

    # Parse SLE15-SP2_Update_25 to 15.2u25
    def parse_cs_line(self, cs):
        rt = 'rt' if '-RT' in cs else ''

        sle, _, u = cs.replace('SLE', '').replace('-RT', '').split('_')
        if '-SP' in sle:
            sle, sp = sle.split('-SP')
        else:
            sle, sp = sle, '0'

        return int(sle), int(sp), int(u), rt

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
            sle, sp, u, rt = self.parse_cs_line(full_cs)
            if rt:
                cs_key = f'{sle}.{sp}{rt}u{u}'
            else:
                cs_key = f'{sle}.{sp}u{u}'

            codestreams[cs_key] = {
                    'project' : proj,
                    'kernel' : kernel,
                    'build-counter' : kernel_full[-1],
                    'branch' : '',
                    'sle' : sle,
                    'sp' : sp,
                    'update' : u,
            }

            if rt:
                codestreams[cs_key]['rt'] = True

        return codestreams

    def setup_project_files(self):
        # Always get the latest supported.csv file and check the content
        # against the codestreams informed by the user
        all_codestreams = self.download_supported_file()

        # Called at this point because codestreams is populated
        self.conf['commits'] = self.ksrc.get_commits(self.conf['cve'])

        # do not get the commits twice
        patched_kernels = self.conf.get('patched_kernels', [])
        if not patched_kernels:
            patched_kernels = self.ksrc.get_patched_kernels(self.conf['commits'])

        self.conf['patched_kernels'] = patched_kernels

        cs_data_missing = {}

        # list of codestreams that matches the file-funcs argument
        working_cs = {}
        patched_cs = []

        for cs, data in all_codestreams.items():
            # Only process codestreams that are related to the argument
            if not re.match(self.codestream, cs):
                continue

            # Skip patched codestreams
            if data['kernel'] in patched_kernels:
                patched_cs.append(cs)
                continue

            data['files'] = self.file_funcs
            data['repo'] = self.cs_repo(cs)

            # The ext_symbols will be populated by ccp
            for file in self.file_funcs.keys():
                data['ext_symbols'] = { file : [] }

            # Set supported archs for the codestream
            # RT is supported only on x86_64 at the moment
            archs = ['x86_64']
            if not data.get('rt', False):
                archs.append('ppc64le')

                if self.is_s390_supported(cs):
                    archs.append('s390x')

            data['archs'] = archs

            if not self.get_data_dir(cs, 'x86_64').is_dir():
                cs_data_missing[cs] = data

            working_cs[cs] = data

        if patched_cs:
            print('Skipping already patched codestreams:')
            print(f'\t{" ".join(patched_cs)}')

        # Add new codestreams to the already existing list, skipping duplicates
        self.conf['patched_cs'] = natsorted(list(set(self.conf.get('patched_cs', []) +
                                      patched_cs)))

        # cpp will use this data in the next step
        with open(self.conf_file, 'w') as f:
            f.write(json.dumps(self.conf, indent=4, sort_keys=True))

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
            # Check if the files exist in the respective codestream directories
            sdir = self.get_sdir(cs)
            for f, fdata in data['files'].items():
                fdir = Path(sdir, f)
                if not fdir.is_file():
                    raise RuntimeError(f'{cs}: File {fdir} doesn\'t exists in {str(sdir)}')

                mod = fdata['module']
                # Use x86_64 to find the module, as it is be the same path for other archs
                obj = self.find_module_obj('x86_64', cs, mod, check_support=True)
                data['object'] = obj

                # Verify if the functions exist in the specified object
                for func in fdata['symbols']:
                    archs = self.check_symbol_archs(cs, func, mod)
                    if archs:
                        archs_str = ','.join(archs)
                        print(f'WARN: {cs}({archs_str}): Function {f}:{func} doesn\'t exist in {obj}')

        # Update and save codestreams data
        for cs, data in self.working_cs.items():
            self.codestreams[cs] = data

        self.flush_cs_file()

    def cs_repo(self, cs):
        sle, sp, up, rt = self.get_cs_tuple(cs)
        if up == 0:
            return 'standard'

        repo = f"SUSE_SLE-{sle}"
        if sp != 0:
            repo = f"{repo}-SP{sp}"

        repo = f'{repo}_Update'

        if rt:
            repo = f'{repo}_Products_SLERT_Update'

        return repo

    # s390x is enabled on 12.4 and 12.5 for all updates.
    # s390x is not supported on 15.1
    # s390x is supported from 15.2 onwards.
    def is_s390_supported(self, cs):
        sle, sp, up, rt = self.get_cs_tuple(cs)

        if (sle == 12 and sp >= 4) or (sle == 15 and sp >= 2):
            return True

        return False
