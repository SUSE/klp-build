from collections import OrderedDict
import copy
import json
import git
import logging
from natsort import natsorted
from pathlib import Path
import platform
import os
import re
import shutil
import subprocess

from lp_utils import classify_codestreams

class Config:
    def __init__(self, bsc, bsc_filter, skips = '', working_cs = {}):
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
        self.skips = skips
        self.arch = platform.processor()

        self.archs = ['ppc64le', 's390x', 'x86_64']

        self.working_cs = OrderedDict(working_cs)
        self.codestreams = OrderedDict()
        self.cs_file = Path(self.bsc_path, 'codestreams.json')
        if self.cs_file.is_file():
            with open(self.cs_file) as f:
                self.codestreams = json.loads(f.read(),
                                              object_pairs_hook=OrderedDict)

        self.conf = OrderedDict({
                'bsc' : str(self.bsc_num),
                'work_dir' : str(self.bsc_path),
                'data' : str(self.data)
        })

        self.conf_file = Path(self.bsc_path, 'conf.json')
        if self.conf_file.is_file():
            with open(self.conf_file) as f:
                self.conf = json.loads(f.read(), object_pairs_hook=OrderedDict)

        # will contain the nm output from the to be livepatched object
        # cache nm calls for the codestream : object
        self.nm_out = {}

        logging.basicConfig(level=logging.INFO, format='%(message)s')

        gcc_ver = int(subprocess.check_output(['gcc',
                                               '-dumpversion']).decode().strip())
        # gcc12 and higher have a problem with kernel and xrealloc implementation
        if gcc_ver < 12:
            self.cc = 'gcc'
        # if gcc12 or higher is the default compiler, check if gcc7 is available
        elif shutil.which('gcc-7'):
            self.cc = 'gcc-7'
        else:
            raise RuntimeError('Only gcc12 or higher are available, and it\'s problematic with kernel sources')

    def lp_out_file(self, fname):
        fpath = f'{str(fname).replace("/", "_").replace("-", "_")}'
        return f'{self.bsc}_{fpath}'

    def get_patches_dir(self):
        return Path(self.bsc_path, 'fixes')

    def remove_patches(self, cs, fil):
        sdir = self.get_sdir(cs)
        kernel = self.get_cs_kernel(cs)
        # Check if there were patches applied previously
        patches_dir = Path(sdir, 'patches')
        if not patches_dir.exists():
            return

        fil.write(f'\nRemoving patches from {cs}({kernel})\n')
        fil.flush()
        err = subprocess.run(['quilt', 'pop', '-a'], cwd=sdir,
                             stderr=fil, stdout=fil)

        if err.returncode not in [0, 2]:
            raise RuntimeError(f'{cs}: quilt pop failed: {err.stderr}')

        shutil.rmtree(patches_dir, ignore_errors=True)
        shutil.rmtree(Path(sdir, ".pc"), ignore_errors=True)

    def apply_all_patches(self, cs, fil=subprocess.STDOUT):
        patched = False

        sle, sp, u, rt = self.get_cs_tuple(cs)

        if rt:
            patch_dirs = [f'{sle}.{sp}{rt}']
        else:
            patch_dirs = [f'{sle}.{sp}']

        if sle == 12:
            patch_dirs.append('cve-4.12')
        elif sle == 15 and sp < 4:
            patch_dirs.append('cve-5.3')

        sdir = self.get_sdir(cs)
        kernel = self.get_cs_kernel(cs)
        for d in patch_dirs:
            pdir = Path(self.get_patches_dir(), d)
            if not pdir.exists():
                fil.write(f'\nPatches dir {pdir} doesnt exists\n')
                continue

            fil.write(f'\nApplying patches on {cs}({kernel}) from {pdir}\n')
            fil.flush()

            for patch in sorted(pdir.iterdir(), reverse=True):
                err = subprocess.run(['quilt', 'import', str(patch)],
                                     cwd=sdir, stderr=fil, stdout=fil)
                if err.returncode != 0:
                    fil.write('\nFailed to import patches, remove applied and try again\n')
                    self.remove_patches(cs, fil)

            err = subprocess.run(['quilt', 'push', '-a'], cwd=sdir,
                                 stderr=fil, stdout=fil)

            if err.returncode != 0:
                fil.write('\nFailed to apply patches, remove applied and try again\n')
                self.remove_patches(cs, fil)

                continue

            patched = True
            fil.flush()
            # Stop the loop in the first dir that we find patches.
            break

        if not patched:
            raise RuntimeError(f'{cs}: Failed to apply patches. Aborting')

    def get_cs_archs(self, cs):
        return self.get_cs_data(cs)['archs']

    def get_cs_dir(self, cs, app):
        return Path(self.bsc_path, app, cs)

    def get_work_dir(self, cs, fname, app):
        fpath = f'work_{str(fname).replace("/", "_")}'
        return Path(self.get_cs_dir(cs, app), fpath)

    def get_cs_data(self, cs):
        if self.working_cs.get(cs, ''):
            return self.working_cs[cs]

        return self.codestreams[cs]

    def get_cs_modules(self, cs):
        return self.get_cs_data(cs)['modules']

    def get_cs_kernel(self, cs):
        return self.get_cs_data(cs)['kernel']

    def get_cs_files(self, cs):
        return self.get_cs_data(cs)['files']

    def get_cs_tuple(self, cs):
        match = re.search('(\d+)\.(\d+)(rt)?u(\d+)', cs)

        return (int(match.group(1)), int(match.group(2)), int(match.group(4)),
                match.group(3))

    def validate_config(self, cs, conf):
        for arch in self.get_cs_archs(cs):
            kconf = self.get_cs_boot_file(cs, 'config', arch)
            with open(kconf) as f:
                match = re.search(f'{conf}=[ym]', f.read())
                if not match:
                    raise RuntimeError(f'{cs}:{arch}: Config {conf} not enabled')

    def missing_codestream(self, cs):
        return not self.get_cs_boot_file(cs, 'config').exists()

    def cs_is_rt(self, cs):
        return self.get_cs_data(cs).get('rt', False)

    def get_ktype(self, cs):
        return 'rt' if self.cs_is_rt(cs) else 'default'

    def get_cs_boot_file(self, cs, file, arch=''):
        if not arch:
            arch = self.arch

        return Path(self.get_data_dir(self.arch), 'boot',
                    f'{file}-{self.get_cs_kernel(cs)}-{self.get_ktype(cs)}')

    def get_data_dir(self, arch):
        return Path(self.data, arch)

    def get_sdir(self, cs):
        kdir = '-rt'
        if not self.cs_is_rt(cs):
            kdir = ''

        return Path(self.get_data_dir(self.arch), 'usr', 'src',
                        f"linux-{self.get_cs_kernel(cs)}{kdir}")

    def get_odir(self, cs):
        return Path(f'{self.get_sdir(cs)}-obj', self.arch, self.get_ktype(cs))

    def get_ipa_file(self, cs, fname):
        return Path(self.get_odir(cs), f'{fname}.000i.ipa-clones')

    def get_mod_path(self, cs, arch):
        kdir = 'default'
        if self.cs_is_rt(cs):
            kdir = 'rt'

        return Path(self.get_data_dir(arch), 'lib', 'modules',
                    f'{self.get_cs_kernel(cs)}-{kdir}')

    def flush_cs_file(self):
        with open(self.cs_file, 'w') as f:
            f.write(json.dumps(self.codestreams, indent=4))

    def is_mod(self, mod):
        return mod != 'vmlinux'

    def get_module_obj(self, arch, cs, module):
        ex_dir = self.get_data_dir(arch)

        # We already search if the module exists on setup phase, so only search
        # for the module when looking for externalized symbols
        obj = self.get_cs_modules(cs).get(module, '')
        if not obj:
            obj = self.find_module_obj(arch, cs, module)

        if not self.is_mod(module):
            return str(Path(ex_dir, obj))

        return str(Path(self.get_mod_path(cs, arch), obj))

    # Return only the name of the module to be livepatched
    def find_module_obj(self, arch, cs, mod, check_support=False):
        kernel = self.get_cs_kernel(cs)
        if not self.is_mod(mod):
            return f'boot/vmlinux-{kernel}-{self.get_ktype(cs)}'

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

        if verbose:
            logging.info('Checking filter and skips...')
        filtered = []
        for cs in full_cs.keys():
            if self.filter and not re.match(self.filter, cs):
                filtered.append(cs)
            elif self.skips and re.match(self.skips, cs):
                filtered.append(cs)

        if verbose:
            if filtered:
                logging.info('Skipping codestreams:')
                logging.info(f'\t{" ".join(classify_codestreams(filtered))}')

        cs_del_list.extend(filtered)

        for cs in cs_del_list:
            full_cs.pop(cs, '')

        keys = natsorted(full_cs.keys())
        return OrderedDict((k, full_cs[k]) for k in keys)

    # Cache the output of nm by using the object path. It differs for each
    # codestream and architecture
    # Return all the symbols not found per arch/obj
    def check_symbol(self, arch, cs, mod, symbols):
        self.nm_out.setdefault(arch, {})
        self.nm_out[arch].setdefault(cs, {})

        if not self.nm_out[arch][cs].get(mod, ''):
            obj = self.get_module_obj(arch, cs, mod)
            self.nm_out[arch][cs][mod] = subprocess.check_output(['nm',
                                                                     '--defined-only',
                                                                     obj]).decode().strip()

        ret = []

        for symbol in symbols:
            syms = re.findall(r'[\w]+ \w {}\n'.format(symbol), self.nm_out[arch][cs][mod])
            if len(syms) == 0:
                ret.append(symbol)

            elif len(syms) > 1:
                print(f'WARNING: {cs}: symbol {symbol} duplicated on {mod}')

            # If len(syms) == 1 means that we found a unique symbol, which is
            # what we expect, and nothing need to be done.

        return ret

    def check_symbol_archs(self, cs, mod, symbols, x86=False):
        data = self.get_cs_data(cs)
        arch_sym = {}
        # Validate only architectures supported by the codestream
        for arch in data['archs']:

            # Avoid rechecking on checking for externalized symbols
            if arch == 'x86_64' and not x86:
                continue

            # Skip if the arch is not supported by the livepatch code
            if not arch in self.conf.get('archs'):
                continue

            # Assign the not found symbols on arch
            syms = self.check_symbol(arch, cs, mod, symbols)
            if syms:
                arch_sym[arch] = syms

        return arch_sym
