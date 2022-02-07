import glob
import json
import pathlib
import os
import re
import requests
import subprocess

import templ

class Setup:
    _cs = {}
    _cs_file = None
    _cve_branches = []

    def __init__(self, destination, redownload, bsc, cve, conf,
                file_funcs, mod, ups_commits):
        # Prefer the argument over the environment
        if not destination:
            destination = pathlib.Path(os.getenv('KLP_ENV_DIR'))
            if not destination:
                raise ValueError('--dest or KLP_ENV_DIR should be defined')

        self._env = pathlib.Path(destination)
        self._work = pathlib.Path(os.getenv('KLP_WORK_DIR'))

        self._bsc_num = re.search('([0-9]+)', bsc).group(1)
        self._bsc = 'bsc' + self._bsc_num
        self._bsc_path = pathlib.Path(self._work, self._bsc)
        if self._bsc_path.exists() and not self._bsc_path.is_dir():
            raise ValueError('--bsc needs to be a directory, or not to exist')

        self._bsc_path.mkdir(exist_ok=True)

        self._cve = re.search('([0-9]+\-[0-9]+)', cve).group(1)
        self._conf = conf
        self._file_funcs = file_funcs
        self._commits = { 'upstream' : {} }
        for commit in ups_commits:
            commit = commit[:12]
            self._commits['upstream'][commit] = self.get_commit_subject(commit)

        # FIXME: currently run-ccp.sh only accepts one file + multiple
        # functions, so grab the first file-func argument as use to create the
        # setup.sh file
        # file_funcs has the content like
        # [ ['fs/file.c', 'func1', 'func2'], ['fs/open.c', 'func3', 'func4']
        # Get the file from the first file-func argument
        self._src = file_funcs[0][0]
        # Return the files from the first file-func argument
        self._funcs = file_funcs[0][1:]
        self._mod = mod

        if not self._env.is_dir():
            raise ValueError('Destiny should be a directory')

        self._redownload = redownload

        self._rpm_dir = pathlib.Path(self._env, 'kernel-rpms')
        self._ex_dir = pathlib.Path(self._env, 'ex-kernels')
        self._ipa_dir = pathlib.Path(self._env, 'ipa-clones')

    def get_rename_prefix(self, cs):
        if 'SLE12-SP3' in cs:
            return 'kgr'
        return 'klp'

    def find_cs_file(self, err=False):
        # If _cs_file is populated, so is _codestreams
        if self._cs_file:
                return

        # If KLP_CS_FILE env var is populated, is must be a valid file
        self._cs_file = os.getenv('KLP_CS_FILE')
        if self._cs_file and not os.path.isfile(self._cs_file):
            raise ValueError(self._cs_file + ' is not a valid file!')

        if not self._cs_file:
            self._cs_file = pathlib.Path(self._bsc_path, 'codestreams.in')

        # If err is true, return error instead of only populare cs_file member
        if err and not self._cs_file.is_file():
            raise ValueError('Couldn\'t find codestreams.in file')

    def download_codestream_file(self):
        self.find_cs_file()

        if os.path.isfile(self._cs_file) and not self._redownload:
            print('Found codestreams.in file, skipping download.')
            return
        elif not self._cs_file:
            self._cs_file = pathlib.Path(self._bsc_path, 'codestreams.in')

        print('Downloading the codestreams.in file into ' + str(self._cs_file))
        req = requests.get('https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv')

        # exit on error
        req.raise_for_status()

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
                rpm_name = 'rpm-' + re.sub('\.\d+$', '', columns[2])

                f.write(columns[0] + ',' + columns[1] + ',' + columns[2] + ',,' + rpm_name + '\n')

    def write_setup_script(self, cs, dest):
        cs_dir = pathlib.Path(dest, cs, 'x86_64')
        cs_dir.mkdir(parents=True, exist_ok=True)

        setup = pathlib.Path(cs_dir, 'setup.sh')

        # Create a work_{file}.c structure to be used in run-ccp.sh
        work_dir = 'work_' + pathlib.Path(self._src).name
        work_path = pathlib.Path(setup.with_name(work_dir))
        work_path.mkdir(parents=True, exist_ok=True)

        src = pathlib.Path(self._ex_dir, cs, 'usr', 'src')
        sdir = pathlib.Path(src, self._cs[cs]['kernel'])
        odir = pathlib.Path(src, self._cs[cs]['kernel'] + '-obj', 'x86_64',
                                'default')
        symvers = pathlib.Path(odir, 'Module.symvers')

        if not self._mod:
            obj = pathlib.Path(self._ex_dir, cs, 'x86_64', 'boot', 'vmlinux-' +
                    self._cs[cs]['kernel'].replace('linux-', '') + '-default')
        else:
            mod_file = self._mod + '.ko'
            obj_path = pathlib.Path(self._ex_dir, cs, 'x86_64', 'lib', 'modules')
            obj = glob.glob(str(obj_path) + '/**/' + mod_file, recursive=True)

            if not obj or len(obj) > 1:
                raise RuntimeError('Module list has none or too much entries: ' + str(obj))
            # Grab the only value of the list and turn obj into a string to be
            # used later
            obj = obj[0]

        ipa = pathlib.Path(self._ipa_dir, cs, 'x86_64', self._src + '.000i.ipa-clones')

        # TODO: currently run-ccp.sh only handles one file + functions, so pick
        # the first one in this case
        with setup.open('w') as f:
            f.write('export KCP_FUNC={}\n'.format(','.join(self._funcs)))
            f.write('export KCP_PATCHED_SRC={}\n'.format(self._src))
            f.write('export KCP_DEST={}\n'.format(str(dest)))
            # FIXME: check which readelf to use
            f.write('export KCP_READELF={}\n'.format('readelf'))
            f.write('export KCP_RENAME_PREFIX={}\n'.format(self.get_rename_prefix(cs)))
            f.write('export KCP_WORK_DIR={}\n'.format(work_path))
            f.write('export KCP_KBUILD_SDIR={}\n'.format(sdir))
            f.write('export KCP_KBUILD_ODIR={}\n'.format(odir))
            f.write('export KCP_MOD_SYMVERS={}\n'.format(symvers))
            f.write('export KCP_PATCHED_OBJ={}\n'.format(obj))
            f.write('export KCP_IPA_CLONES_DUMP={}\n'.format(ipa))

    def prepare_bsc_dirs(self):
        self.find_cs_file(err=True)

        if not self._ex_dir.is_dir() or not self._ipa_dir.is_dir():
            print(self._ex_dir, self._ipa_dir)
            raise RuntimeError('KLP_ENV_DIR was not defined, or ex-kernel/ipa-clones does not exist')

        # Create the necessary directories for each codestream and populate the
        # setup.sh script
        for cs in self._cs.keys():
            dest = pathlib.Path(self._bsc_path, 'c')
            dest.mkdir(parents=True, exist_ok=True)

            self.write_setup_script(cs, dest)

    def get_commit_subject(self, commit):
        req = requests.get('https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={}'.format(commit))
        req.raise_for_status()

        # Save the upstream commit in the bsc directory
        fpath = pathlib.Path(self._bsc_path, 'commit.patch')
        with open(fpath, 'w') as f:
            f.write(req.text)

        return re.search('Subject: (.*)', req.text).group(1)

    def get_commits(self):
        ksource_git = os.getenv('KLP_KERNEL_SOURCE', '')
        if not ksource_git:
            return

        ksource_path = pathlib.Path(ksource_git)
        if not ksource_path.is_dir():
            return

        # Get backported commits from the CVE branches
        for bc in self._cve_branches:
            self._commits[bc] = {}
            for commit, msg in self._commits['upstream'].items():
                # FIXME: commit_hash will contain double quotes, and when
                # writing the json file it'll add quotes again. I need to find
                # why...
                commit_hash = subprocess.check_output(['/usr/bin/git', '-C', str(ksource_path),
                            'log', '--pretty="%H"', '--grep',  msg,
                            'remotes/origin/cve/linux-' + bc],
                            stderr=subprocess.PIPE)
                cmt = commit_hash.decode('ascii').strip().replace('"', '')
                # We don't care about branches commit message, because it is the
                # same as the upstream commit
                self._commits[bc][cmt] = ''

    def write_conf_json(self):
        files = {}

        for f in self._file_funcs:
            filepath = f[0]
            funcs = f[1:]
            files[filepath] = funcs

        data = { 'bsc' : self._bsc_num,
                'cve' : self._cve,
                'conf' : self._conf,
                'mod' : self._mod,
                'cve_branches' : self._cve_branches,
                'commits' : self._commits,
                'files' : files }
        with open(pathlib.Path(self._bsc_path, 'conf.json'), 'w') as f:
            f.write(json.dumps(data, indent=4))

    def write_commit_file(self):
        temp = templ.Template(self._bsc, 'klp')
        msg = temp.generate_commit_msg()

        with open(pathlib.Path(self._bsc_path, 'commit.msg'), 'w') as f:
            f.write(msg)

    def download_env(self):
        print('FIXME: implement the download and extraction of kernel rpms and ipa-clones')

    def prepare_env(self):
        self.download_codestream_file()

        cve_branches = []

        with self._cs_file.open() as cs_file:
            for line in cs_file:
                cs, target, rel, _, kernel = line.strip().split(',')
                self._cs[cs] = { 'target' : target, 'kernel' : kernel.replace('rpm', 'linux') }

                # do not expect any problems with the kernel release format
                cve_branches.append(re.search('^([0-9]+\.[0-9]+)', rel).group(1))

            # remove the duplicate entries
            self._cve_branches = list(dict.fromkeys(cve_branches))

        self.prepare_bsc_dirs()
        self.get_commits()
        self.write_conf_json()
        self.write_commit_file()
