import glob
import json
import pathlib
import os
import re
import requests
import shutil
import subprocess

import templ

class Setup:
    _cs_file = None
    _cs_json = {}
    _cve_branches = []

    def __init__(self, data, work_dir, redownload, bsc, cve, conf,
                file_funcs, mod, ups_commits):
        # Prefer the argument over the environment
        if not data:
            data = pathlib.Path(os.getenv('KLP_DATA_DIR'))
            if not data:
                raise ValueError('--data or KLP_DATA_DIR should be defined')

        self._env = pathlib.Path(data)
        # Prefer the argument over the environment
        if not work_dir:
            work_dir = pathlib.Path(os.getenv('KLP_WORK_DIR'))
            if not work_dir:
                raise ValueError('--work-dir or KLP_WORK_DIR should be defined')

        self._work = work_dir

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

        # file_funcs has the content like
        # [ ['fs/file.c', 'func1', 'func2'], ['fs/open.c', 'func3', 'func4']
        self._src = []
        self._funcs = []
        for ff in file_funcs:
            self._src.append(ff[0])
            self._funcs.append(','.join(ff[1:]))

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

    def download_codestream_file(self):
        self._cs_file = pathlib.Path(self._bsc_path, 'codestreams.in')

        if os.path.isfile(self._cs_file) and not self._redownload:
            print('Found codestreams.in file, skipping download.')
            return

        req = requests.get('https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv')

        # exit on error
        req.raise_for_status()

        # For now let's keep the current format of codestreams.in and
        # codestreams.json
        first_line = True
        kernels = []
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
                kernel = re.sub('\.\d+$', '', columns[2])

                f.write(columns[0] + ',' + columns[1] + ',' + columns[2] + ',,rpm-' + kernel + '\n')

                sle, _, u = columns[0].replace('SLE', '').split('_')
                if '-SP' in sle:
                    sle = sle.replace('-SP', '.')
                else:
                    sle = sle + '.0'
                self._cs_json[sle + 'u' + u] = {
                    'project' : columns[1],
                    'kernel' : kernel,
                    'micro-version' : columns[2][-1],
                    'branch' : '',
                    'cs' : columns[0]
                }

                # do not expect any problems with the kernel release format
                kernels.append(re.search('^([0-9]+\.[0-9]+)', kernel).group(1))

        # We create a dict to remove the duplicate kernel versions, used as CVE
        # branches for find the fixes for each codestreams in kernel-source
        # later on
        self._cve_branches = list(dict.fromkeys(kernels))

    def write_setup_script(self, cs):
        jcs = self._cs_json[cs]

        # Use the old full codestream name to avoid problems for now
        full_cs = jcs['cs']

        cs_dir = pathlib.Path(self._bsc_path, 'c', full_cs, 'x86_64')
        cs_dir.mkdir(parents=True, exist_ok=True)

        setup = pathlib.Path(cs_dir, 'setup.sh')

        # Create a work_{file}.c structure to be used in run-ccp.sh
        work_paths = []
        for src in self._src:
            work_dir = 'work_' + pathlib.Path(src).name
            work_path = pathlib.Path(setup.with_name(work_dir))

            # remove any previously generated files
            shutil.rmtree(work_path, ignore_errors=True)

            # recreate the directory to run ccp on it
            work_path.mkdir(parents=True, exist_ok=True)

            work_paths.append(str(work_path))

        ex_dir = pathlib.Path(self._ex_dir, full_cs)
        ipa_dir = pathlib.Path(self._ipa_dir, full_cs)

        kernel = jcs['kernel']

        src = pathlib.Path(ex_dir, 'usr', 'src')
        sdir = pathlib.Path(src, 'linux-' + kernel)
        odir = pathlib.Path(src, 'linux-' + kernel + '-obj', 'x86_64', 'default')
        symvers = pathlib.Path(odir, 'Module.symvers')

        if not self._mod:
            obj = pathlib.Path(ex_dir, 'x86_64', 'boot', 'vmlinux-' +
                    kernel.replace('linux-', '') + '-default')
        else:
            mod_file = self._mod + '.ko'
            obj_path = pathlib.Path(ex_dir, 'x86_64', 'lib', 'modules')
            obj = glob.glob(str(obj_path) + '/**/' + mod_file, recursive=True)

            if not obj or len(obj) > 1:
                raise RuntimeError('Module list has none or too much entries: ' + str(obj))
            # Grab the only value of the list and turn obj into a string to be
            # used later
            obj = obj[0]

        ipa_src = []
        for src in self._src:
            ipa_src.append(str(pathlib.Path(ipa_dir, 'x86_64', src + '.000i.ipa-clones')))

        with setup.open('w') as f:
            f.write('export KCP_FUNC="{}"\n'.format(';'.join(self._funcs)))
            f.write('export KCP_PATCHED_SRC="{}"\n'.format(';'.join(self._src)))
            #f.write('export KCP_DEST={}\n'.format(str(dest)))
            # FIXME: check which readelf to use
            f.write('export KCP_READELF={}\n'.format('readelf'))
            f.write('export KCP_RENAME_PREFIX={}\n'.format(self.get_rename_prefix(full_cs)))
            f.write('export KCP_WORK_DIR="{}"\n'.format(';'.join(work_paths)))
            f.write('export KCP_KBUILD_SDIR={}\n'.format(sdir))
            f.write('export KCP_KBUILD_ODIR={}\n'.format(odir))
            f.write('export KCP_MOD_SYMVERS={}\n'.format(symvers))
            f.write('export KCP_PATCHED_OBJ={}\n'.format(obj))
            f.write('export KCP_IPA_CLONES_DUMP="{}"\n'.format(';'.join(ipa_src)))

        jcs['readelf'] = 'readelf'
        jcs['rename_prefix'] = self.get_rename_prefix(full_cs)
        jcs['work_dir'] = work_paths
        jcs['sdir'] = str(sdir)
        jcs['odir'] = str(odir)
        jcs['symvers'] = str(pathlib.Path(odir, 'Module.symvers'))
        jcs['object'] = str(obj)
        jcs['ipa_clones'] = ipa_src

    def prepare_bsc_dirs(self):
        if not self._ex_dir.is_dir() or not self._ipa_dir.is_dir():
            raise RuntimeError('KLP_DATA_DIR was not defined, or ex-kernel/ipa-clones does not exist')

        # Create the necessary directories for each codestream and populate the
        # setup.sh script
        for cs in self._cs_json.keys():
            self.write_setup_script(cs)

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

    def write_json_files(self):
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

        with open(pathlib.Path(self._bsc_path, 'codestreams.json'), 'w') as f:
            f.write(json.dumps(self._cs_json, indent=4))

    def write_commit_file(self):
        temp = templ.Template(self._bsc, self._work, 'klp')
        msg = temp.generate_commit_msg()

        with open(pathlib.Path(self._bsc_path, 'commit.msg'), 'w') as f:
            f.write(msg)

    def download_env(self):
        print('FIXME: implement the download and extraction of kernel rpms and ipa-clones')

    def prepare_env(self):
        self.download_codestream_file()

        self.prepare_bsc_dirs()
        self.get_commits()
        self.write_json_files()
        self.write_commit_file()
