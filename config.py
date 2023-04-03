import copy
import json
import git
from pathlib import Path
import os
import re
import subprocess

class Config:
    def __init__(self, bsc, bsc_filter, working_cs = {}):
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
        self.scripts = Path(os.path.dirname(__file__), 'scripts')
        self.filter = bsc_filter

        self.archs = ['x86_64', 's390x', 'ppc64le']

        self.working_cs = working_cs
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
        # cache nm calls for the codestream : object
        self.nm_out = {}

    def lp_out_file(self, fname):
        fpath = f'{str(fname).replace("/", "_").replace("-", "_")}'
        return f'{self.bsc}_{fpath}'

    def get_cs_dir(self, cs, arch=''):
        if arch:
            return Path(self.bsc_path, 'c', cs, arch)
        return Path(self.bsc_path, 'c', cs)

    def get_work_dir(self, cs, fname):
        fpath = f'work_{str(fname).replace("/", "_")}'
        return Path(self.get_cs_dir(cs), fpath)

    def get_work_lp_file(self, cs, fname):
        return Path(self.get_work_dir(cs, fname), self.lp_out_file(fname))

    def get_cs_lp_dir(self, cs):
        return Path(self.get_cs_dir(cs), 'lp')

    def get_cs_data(self, cs):
        if self.working_cs.get(cs, ''):
            return self.working_cs[cs]

        return self.codestreams[cs]

    def get_cs_archs(self, cs):
        return self.get_cs_data(cs)['archs']

    def get_cs_object(self, cs):
        return self.get_cs_data(cs).get('object', '')

    def get_cs_kernel(self, cs):
        return self.get_cs_data(cs)['kernel']

    def get_cs_files(self, cs):
        return self.get_cs_data(cs)['files']

    def get_cs_ext_symbols(self, cs):
        return self.get_cs_data(cs)['ext_symbols']

    def get_cs_tuple(self, cs):
        match = re.search('(\d+)\.(\d+)(rt)?u(\d+)', cs)

        return (int(match.group(1)), int(match.group(2)), int(match.group(4)),
                match.group(3))

    def get_data_dir(self, cs='', arch=''):
        if not cs:
            return self.data
        if not arch:
            return Path(self.data, cs)
        return Path(self.data, cs, arch)

    def get_ipa_dir(self, cs, arch='x86_64'):
        return Path(self.get_data_dir(cs, arch), 'ipa-clones')

    def cs_is_rt(self, cs):
        return self.get_cs_data(cs).get('rt', False)

    def get_ipa_src_path(self, cs, arch):
        kernel = self.get_cs_kernel(cs)
        if self.cs_is_rt(cs):
            return Path('usr', 'src', f'linux-{kernel}-rt-obj', arch, 'rt')

        return Path('usr', 'src', f'linux-{kernel}-obj', arch, 'default')

    def get_sdir(self, cs):
        kdir = '-rt'
        if not self.cs_is_rt(cs):
            kdir = ''

        return Path(self.data, cs, 'usr', 'src',
                        f"linux-{self.get_cs_kernel(cs)}{kdir}")

    def get_odir(self, cs):
        kdir = 'default'
        if self.cs_is_rt(cs):
            kdir = 'rt'

        return Path('x86_64', kdir)

    def get_mod_path(self, cs, arch):
        kdir = 'default'
        if self.cs_is_rt(cs):
            kdir = 'rt'

        return Path(self.get_data_dir(cs, arch), 'lib', 'modules',
                    f'{self.get_cs_kernel(cs)}-{kdir}')

    def flush_cs_file(self):
        with open(self.cs_file, 'w') as f:
            f.write(json.dumps(self.codestreams, indent=4, sort_keys=True))

    def get_module_obj(self, arch, cs, module, use_cached_obj=True):
        ex_dir = self.get_data_dir(cs, arch)

        # Use the object if it was previously set, and if we are trying to find
        # symbols for the to be livepatched module. We can also search for
        # symbols in externalized functions, so this argument checks
        obj = ''
        if use_cached_obj:
            obj = self.get_cs_object(cs)

        if not obj:
            obj = self.find_module_obj(arch, cs, module)

        mod = self.conf['mod']
        if mod == 'vmlinux':
            return str(Path(ex_dir, obj))

        return str(Path(self.get_mod_path(cs, arch), obj))

    # Return only the name of the module to be livepatched
    def find_module_obj(self, arch, cs, mod, check_support=False):
        kernel = self.get_cs_kernel(cs)
        if mod == 'vmlinux':
            ktype = 'default'
            if self.cs_is_rt(cs):
                ktype = 'rt'
            return f'boot/vmlinux-{kernel}-{ktype}'

        # mod here can be using _ but the filename can be using -, so replace
        # the _ cases with a regex like form to check for both _ and -
        mod = mod.replace('_', '[-_]')

        mod_path = self.get_mod_path(cs, arch)
        with open(Path(mod_path, 'modules.order')) as f:
            obj = re.search(f'([\w\/\-]+\/{mod}.ko)', f.read())
            if not obj:
                raise RuntimeError(f'{cs}: Module not found: {mod}')


            obj = obj.group(1)
            obj_path = str(Path(mod_path, obj))

            # Validate if the module being livepatches is supported or not
            out = subprocess.check_output(['/sbin/modinfo', obj_path],
                                          stderr=subprocess.STDOUT).decode()

            if check_support and re.search('supported:\s+no', out):
                print(f'WARN: {cs}: Module {mod} is not supported by SLE')

            return obj

    # Return the codestreams list but removing already patched codestreams,
    # codestreams without file-funcs and not matching the filter
    def filter_cs(self, cs_list=None, verbose=True):
        cs_del_list = []
        if not cs_list:
            cs_list = self.codestreams
        full_cs = copy.deepcopy(cs_list)

        if self.filter:
            if verbose:
                print('Applying filter...')
            filtered = []
            for cs in full_cs.keys():
                if not re.match(self.filter, cs):
                    filtered.append(cs)

            if verbose:
                print('Skipping codestreams:')
                print(f'\t{" ".join(filtered)}')

            cs_del_list.extend(filtered)

        for cs in cs_del_list:
            full_cs.pop(cs, '')

        return full_cs

    # Cache the output of nm by using the object path. It differs for each
    # codestream and architecture
    def check_symbol(self, arch, cs, symbol, mod):
        self.nm_out.setdefault(arch, {})
        self.nm_out[arch].setdefault(cs, {})

        if not self.nm_out[arch][cs].get(mod, ''):
            obj = self.get_module_obj(arch, cs, mod, use_cached_obj=False)
            self.nm_out[arch][cs][mod] = subprocess.check_output(['nm',
                                                                     '--defined-only',
                                                                     obj]).decode().strip()

        return re.search(r' {}\n'.format(symbol), self.nm_out[arch][cs][mod])

    def check_symbol_archs(self, cs, symbol, mod):
        data = self.get_cs_data(cs)
        arch_sym = []
        # Validate only architectures supported by the codestream
        for arch in data['archs']:

            # The livepatch creator usually do it on a x86_64 machine, so the
            # check for this arch was already done
            if arch == 'x86_64':
                continue

            # Skip if the arch is not supported by the livepatch code
            if not arch in self.conf.get('archs'):
                continue

            if self.check_symbol(arch, cs, symbol, mod):
                continue

            # Add the arch to the dict if the symbol wasn't found
            arch_sym.append(arch)

        return arch_sym
