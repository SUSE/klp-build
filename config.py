import json
import git
from pathlib import Path
import os
import re
import subprocess

class Config:
    def __init__(self, bsc, bsc_filter):
        work_dir = os.getenv('KLP_WORK_DIR')
        if not work_dir:
            raise ValueError('KLP_WORK_DIR should be defined')

        work = Path(work_dir)
        if not work.is_dir():
            raise ValueError('Work dir should be a directory')

        data = os.getenv('KLP_DATA_DIR', '')
        if not data:
            raise ValueError('KLP_DATA_DIR should be defined')

        self.data = Path(data)
        if not self.data.is_dir():
            raise ValueError('Data dir should be a directory')

        try:
            git_data = git.GitConfigParser()
            self.user = git_data.get_value('user', 'name')
            self.email = git_data.get_value('user', 'email')
        except:
            raise ValueError('Please define name/email in global git config')

        self.bsc_num = bsc
        self.bsc = 'bsc' + str(bsc)
        self.bsc_path = Path(work, self.bsc)
        self.bsc_path.mkdir(exist_ok=True)
        self.filter = bsc_filter

        self.ex_dir = Path(self.data, 'ex-kernels')
        self.ex_dir.mkdir(exist_ok=True)
        self.ipa_dir = Path(self.data, 'ipa-clones')
        self.ipa_dir.mkdir(exist_ok=True)

        self.codestreams = {}
        self.cs_file = Path(self.bsc_path, 'codestreams.json')
        if self.cs_file.is_file():
            with open(self.cs_file) as f:
                self.codestreams = json.loads(f.read())

        self.conf = {
                'bsc' : str(self.bsc_num),
                'work_dir' : str(self.bsc_path),
                'data' : str(self.data)
        }

        self.conf_file = Path(self.bsc_path, 'conf.json')
        if self.conf_file.is_file():
            with open(self.conf_file) as f:
                self.conf = json.loads(f.read())

        # will contain the nm output from the to be livepatched object
        self.nm_out = {}

    def get_work_dir(self, cs):
        return Path(self.bsc_path, 'c', cs, 'x86_64')

    def get_cs_lp_dir(self, cs):
        return Path(self.bsc_path, 'c', cs, 'x86_64', 'lp')

    def get_ex_dir(self, cs='', arch=''):
        if not cs:
            return self.ex_dir
        if not arch:
            return Path(self.ex_dir, cs)
        return Path(self.ex_dir, cs, arch)

    def get_ipa_dir(self, cs='', arch=''):
        if not cs:
            return self.ipa_dir
        if not arch:
            return Path(self.ipa_dir, cs)
        return Path(self.ipa_dir, cs, arch)

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
