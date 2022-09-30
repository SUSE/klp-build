import json
from pathlib import Path
import os
import re
import subprocess

class Config:
    def __init__(self, args):
        self.filter = args.filter
        self.kernel_branches = {
                                '4.12' : 'cve/linux-4.12',
                                '5.3' : 'cve/linux-5.3',
                                '5.14' : 'SLE15-SP4'
                                }

        # Prefer the argument over the environment
        work_dir = args.work_dir
        if not work_dir:
            work_dir = os.getenv('KLP_WORK_DIR')
            if not work_dir:
                raise ValueError('--work-dir or KLP_WORK_DIR should be defined')

        self.work = Path(work_dir)
        if not self.work.is_dir():
            raise ValueError('Work dir should be a directory')

        self.scripts_path = Path(Path().home(), 'kgr', 'scripts')
        if not self.scripts_path.is_dir():
            raise ValueError('Script dir not found in ~/kgr/scripts')

        bsc = args.bsc
        self.bsc_num = bsc
        self.bsc = 'bsc' + str(bsc)
        self.bsc_path = Path(self.work, self.bsc)

        self.data = None

        # We'll create the directory on setup, so we require it to now exists
        if args.cmd == 'setup':
            # We only require --data for setup, since conf.json will contain all
            # relevant data for the later steps
            data = args.data
            # Prefer the argument over the environment
            if not data:
                data = os.getenv('KLP_DATA_DIR', '')
                if not data:
                    raise ValueError('--data or KLP_DATA_DIR should be defined')

            self.data = Path(data)
            if not self.data.is_dir():
                raise ValueError('Data dir should be a directory')

        self.codestreams = {}
        self.cs_file = Path(self.bsc_path, 'codestreams.json')
        if self.cs_file.is_file():
            with open(self.cs_file, 'r') as f:
                self.codestreams = json.loads(f.read())

        # Codestreams remaining after applying filter
        self.working_cs = []

        self.conf = {}
        self.conf_file = Path(self.bsc_path, 'conf.json')
        if self.conf_file.is_file():
            with open(self.conf_file, 'r') as f:
                self.conf = json.loads(f.read())

        # Set self.data from conf.json or from the env var is the args.cmd is
        # not setup
        if not self.data:
            if self.conf.get('data', ''):
                self.data = Path(self.conf['data'])
            else:
                self.data = Path(os.getenv('KLP_DATA_DIR', ''))

        if not self.data.is_dir():
            raise RuntimeError('KLP_DATA_DIR does not exists')

        self.ex_dir = Path(self.data, 'ex-kernels')
        self.ex_dir.mkdir(exist_ok=True)
        self.ipa_dir = Path(self.data, 'ipa-clones')
        self.ipa_dir.mkdir(exist_ok=True)

        self.ksrc = os.getenv('KLP_KERNEL_SOURCE')
        if self.ksrc and not Path(self.ksrc).is_dir():
            raise ValueError('KLP_KERNEL_SOURCE should point to a directory')

        if args.cmd == 'get-patches' and not self.ksrc:
            raise ValueError('KLP_KERNEL_SOURCE should be defined')

        if args.cmd in ['build', 'format-patches', 'ibs']:
            if not self.codestreams:
                raise RuntimeError('codestreams.json doesn\'t exists. Aborting.')

            kgr_patches = Path(Path().home(), 'kgr', 'kgraft-patches')
            if not kgr_patches.is_dir:
                raise RuntimeError('kgraft-patches does not exists in ~/kgr')
            self.kgr_patches = kgr_patches

        # will contain the nm output from the to be livepatched object
        self.nm_out = {}

        # kgraft-patches is only necessary for --push
        if args.cmd == 'ibs' and not args.push:
            kgraft_path = Path(Path().home(), 'kgr', 'kgraft-patches')
            if not kgraft_path.is_dir():
                raise RuntimeError('Couldn\'t find ~/kgr/kgraft-patches')

        if args.cmd == 'ibs' and args.prepare_tests:
            self.kgraft_tests_path = Path(Path().home(), 'kgr',
                                          'kgraft-patches_testscripts')
            if not self.kgraft_tests_path.is_dir():
                raise RuntimeError('Couldn\'t find ~/kgr/kgraft-patches_testscripts')

        self.bsc_path.mkdir(exist_ok=True)

    def get_work_dir(self, cs):
        return Path(self.bsc_path, 'c', cs, 'x86_64')

    def get_cs_lp_dir(self, cs):
        return Path(self.bsc_path, 'c', cs, 'x86_64', 'lp')

    def get_ex_dir(self, cs, arch='x86_64'):
        if not cs:
            return self.ex_dir
        return Path(self.ex_dir, cs, arch)

    def get_ipa_dir(self, cs):
        if not cs:
            return self.ipa_dir
        return Path(self.ipa_dir, cs, 'x86_64')

    def get_sdir(self, cs):
        jcs = self.codestreams[cs]
        return str(Path(self.ex_dir, jcs['cs'], 'usr', 'src',
                        f"linux-{jcs['kernel']}"))

    def get_cs_tuple(self, cs):
        data = self.codestreams[cs]
        return (data['sle'], data['sp'], data['update'])

    def filtered_cs(self):
        if not self.filter:
            return self.codestreams

        result = {}
        for cs, data in self.codestreams.items():
            if not re.match(self.filter, cs):
                continue
            result[cs] = data

        return result

    # Return the codestreams list but removing already patched codestreams,
    # codestreams without file-funcs and not matching the filter
    def filter_cs(self, cs_list, check_file_funcs=False):
        cs_new_list = []

        patched = self.conf.get('patched', [])
        if patched:
            print('Skipping patched codestreams:')
            print(f'\t{" ".join(patched)}')

        cs_new_list = list(set(cs_list) - set(patched))

        if self.filter:
            print('Applying filter...')
            filtered = []
            for cs in cs_new_list:
                if re.match(self.filter, cs):
                    filtered.append(cs)

            print('Skipping codestreams:')
            print(f'\t{" ".join(filtered)}')

            cs_new_list = list(set(cs_new_list) - set(filtered))

        if check_file_funcs:
            filtered = []
            for cs in cs_new_list:
                if not self.codestreams[cs].get('files', ''):
                    filtered.append(cs)

            print('Skipping codestreams without file-funcs:')
            print(f'\t{" ".join(filtered)}')

            cs_new_list = list(set(cs_new_list) - set(filtered))

        return cs_new_list

    # Cache the output of nm by using the object path. It differs for each
    # codestream and architecture
    def check_symbol(self, symbol, obj):
        if not self.nm_out.get(obj, ''):
            self.nm_out[obj] = subprocess.check_output(['nm', obj]).decode().strip()
        return re.search(r' {}\n'.format(symbol), self.nm_out[obj])

    def check_symbol_archs(self, jcs, symbol):
        arch_sym = {}
        for arch in self.conf['archs']:

            # The livepatch creator usually do it on a x86_64 machine, so the
            # check for this arch was already done
            if arch == 'x86_64':
                continue

            obj_path = jcs['object'].replace('x86_64', arch)

            ret = 'ok' if self.check_symbol(symbol, obj_path) else 'NOT FOUND'

            arch_sym[arch] = ret

        return arch_sym
