import concurrent.futures
import errno
from lxml import etree
from pathlib import Path
import os
from osctiny import Osc
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from config import Config
from ksrc import GitHelper

class IBS(Config):
    def __init__(self, bsc, bsc_filter):
        super().__init__(bsc, bsc_filter)
        self.osc = Osc(url='https://api.suse.de')

        self.ibs_user = re.search('(\w+)@', self.email).group(1)
        self.prj_prefix = f'home:{self.ibs_user}:{self.bsc}-klp'

        self.kernel_rpms = Path(self.data, 'kernel-rpms')
        self.kernel_rpms.mkdir(exist_ok=True)

        self.kgraft_path = Path(Path().home(), 'kgr', 'kgraft-patches')
        if not self.kgraft_path.is_dir():
            raise RuntimeError('Couldn\'t find ~/kgr/kgraft-patches')

        self.kgraft_tests_path = Path(Path().home(), 'kgr',
                                      'kgraft-patches_testscripts')
        if not self.kgraft_tests_path.is_dir():
            raise RuntimeError('Couldn\'t find ~/kgr/kgraft-patches_testscripts')

        self.ksrc = GitHelper(self.bsc_num, self.filter)

        # Download all sources for x86
        # For ppc64le and s390x only download vmlinux and the built modules
        self.cs_data = {
                'ppc64le' : {
                    'kernel-default' : '(kernel-default-[\d\.\-]+.ppc64le.rpm)',
                },
                's390x' : {
                    'kernel-default' : '(kernel-default-[\d\.\-]+.s390x.rpm)',
                },
                'x86_64' : {
                    'kernel-default' : '(kernel-default\-(extra|(livepatch|kgraft)?\-?devel)?\-?[\d\.\-]+.x86_64.rpm)',
                    'kernel-source' : '(kernel-(source|devel)\-?[\d\.\-]+.noarch.rpm)'
                }
        }

    def do_work(self, func, args, workers=0):
        if len(args) == 0:
            return

        if workers == 0:
            workers = os.cpu_count()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = executor.map(func, args)
            for result in results:
                if result:
                    print(result)

    # The projects has different format: 12_5u5 instead of 12.5u5
    def get_projects(self):
        prjs = []
        projects = self.osc.search.project("starts-with(@name, '{}')".format(self.prj_prefix))

        for prj in projects.findall('project'):
            prj_name = prj.get('name')
            cs = self.convert_prj_to_cs(prj_name)

            if self.filter and not re.match(self.filter, cs):
                continue

            prjs.append(prj)

        return prjs

    def get_project_names(self):
        names = []
        for result in self.get_projects():
            names.append(result.get('name'))

        return names

    def delete_project(self, prj, verbose=True):
        if not self.osc.projects.exists(prj):
            return

        ret = self.osc.projects.delete(prj)
        if type(ret) is not bool:
            print(etree.tostring(ret))
            raise ValueError(prj)

        if verbose:
            print('\t' + prj)

    def extract_rpms(self, args):
        cs, arch, rpm, dest = args

        fcs = self.codestreams[cs]['cs']
        kernel = self.codestreams[cs]['kernel']

        if 'livepatch' in rpm or 'kgraft-devel' in rpm:
            path_dest = self.get_ipa_dir(fcs, arch)
        elif re.search(   'kernel\-default\-\d+', rpm) or \
                re.search('kernel\-default\-extra\-\d+', rpm):
            path_dest = self.get_ex_dir(fcs, arch)
        else:
            path_dest = self.get_ex_dir(fcs)

        fdest = Path(dest, rpm)
        path_dest.mkdir(exist_ok=True, parents=True)

        cmd = 'rpm2cpio {} | cpio --quiet -idm'.format(str(fdest))
        subprocess.check_output(cmd, shell=True, cwd=path_dest)

        # Move ipa-clone files to path_dest
        if 'livepatch' in rpm or 'kgraft-devel' in rpm:
            src_dir = Path(path_dest, 'usr', 'src',
                                    'linux-{}-obj'.format(kernel),
                                  arch, 'default')

            for f in os.listdir(src_dir):
                shutil.move(Path(src_dir, f), path_dest)

            # remove leftovers
            os.remove(Path(path_dest, 'Symbols.list'))
            shutil.rmtree(Path(path_dest, 'usr'))

        print('Extracting {} {}: ok'.format(cs, rpm))

    def download_and_extract(self, args):
        cs, prj, repo, arch, pkg, rpm, dest = args

        self.download_binary_rpms(args)

        # Do not extract kernel-macros rpm
        if 'kernel-macros' not in rpm:
            self.extract_rpms( (cs, arch, rpm, dest) )

    def download_cs_data(self, cs_list):
        rpms = []
        extract = []

        print('Getting list of files...')
        for cs in cs_list:
            jcs = self.codestreams[cs]
            prj = jcs['project']
            repo = jcs['repo']

            path_dest = Path(self.kernel_rpms, jcs['cs'])
            path_dest.mkdir(exist_ok=True)

            for arch, val in self.cs_data.items():
                if arch not in jcs['archs']:
                    continue

                for k, regex in val.items():
                    if repo == 'standard':
                        pkg = k
                    else:
                        pkg = '{}.{}'.format(k, repo)

                    # arch is fixed for now
                    ret = self.osc.build.get_binary_list(prj, repo, arch, pkg)
                    for file in re.findall(regex, str(etree.tostring(ret))):
                        # FIXME: adjust the regex to only deal with strings
                        if isinstance(file, str):
                            rpm = file
                        else:
                            rpm = file[0]
                        rpms.append( (cs, prj, repo, arch, pkg, rpm, path_dest) )

        print('Downloading {} rpms...'.format(len(rpms)))
        self.do_work(self.download_and_extract, rpms)

        for fext, ecmd in [('zst', 'unzstd --rm -f -d'), ('xz', 'xz -d')]:
            cmd = f'find {self.ex_dir} -name "*ko.{fext}" -exec {ecmd} --quiet {{}} \;'
            subprocess.check_output(cmd, shell=True)

        subprocess.check_output(f'find {self.ex_dir} -name "vmlinux*default.gz" -exec gzip -d {{}} \;',
                                shell=True)

        print('Finished extract vmlinux and modules...')

    def download_binary_rpms(self, args):
        cs, prj, repo, arch, pkg, rpm, dest = args

        try:
            self.osc.build.download_binary(prj, repo, arch, pkg, rpm, dest)
            print('{} {}: ok'.format(cs, rpm))
        except OSError as e:
            if e.errno == errno.EEXIST:
                print('{} {}: already downloaded. skipping.'.format(cs, rpm))
            else:
                raise RuntimeError('download error on {}: {}'.format(prj, rpm))

    def convert_prj_to_cs(self, prj):
        return prj.replace(f'{self.prj_prefix}-', '').replace('_', '.')

    def apply_filter(self, item_list):
        if not self.filter:
            return item_list

        filtered = []
        for item in item_list:
            cmp_item = convert_prj_to_cs(item)
            if not re.match(self.filter, cmp_item):
                continue

            filtered.append(item)

        return filtered

    def find_missing_symbols(self, cs, arch, lp_mod_path):
        kernel = self.codestreams[cs]['kernel']
        full_cs = self.codestreams[cs]['cs']

        # TODO: Change ex_dir codestream names to the new format
        vmlinux_path = Path(self.get_ex_dir(full_cs, arch), 'boot',
                            f'vmlinux-{kernel}-default')

        # Get list of UNDEFINED symbols from the livepatch module
        out = subprocess.check_output(['nm', '--undefined-only', str(lp_mod_path)],
                                      stderr=subprocess.STDOUT).decode()
        # Remove the U flag from every line
        lp_und_symbols = re.findall('\s+U\s([\w]+)', out)

        # vmlinux should have all symbols defined, but let's be safe here too
        vmlinux_syms = subprocess.check_output(['nm', '--defined-only', str(vmlinux_path)],
                                      stderr=subprocess.STDOUT).decode()

        missing_syms = []
        # Find all UNDEFINED symbols that exists in the livepatch module that
        # aren't defined in the vmlinux
        for sym in lp_und_symbols:
            if not re.search(f' {sym}', vmlinux_syms):
                missing_syms.append(sym)

        return missing_syms

    def validate_livepatch_module(self, cs, arch, rpm_dir, rpm):
        match = re.search('(livepatch)-.*default\-(\d+)\-(\d+)\.(\d+)\.(\d+)\.', rpm)
        if match:
            dir_path = match.group(1)
            lp_file = f'livepatch-{match.group(2)}-{match.group(3)}_{match.group(4)}_{match.group(5)}.ko'
        else:
            match = re.search('(kgraft)\-patch\-.*default\-(\d+)\-(\d+)\.(\d+)\.', rpm)
            if match:
                dir_path = match.group(1)
                lp_file = f'kgraft-patch-{match.group(2)}-{match.group(3)}_{match.group(4)}.ko'

        fdest = Path(rpm_dir, rpm)
        # Extract the livepatch module for later inspection
        cmd = 'rpm2cpio {} | cpio --quiet -idm'.format(str(fdest))
        subprocess.check_output(cmd, shell=True, cwd=rpm_dir)

        kernel = self.codestreams[cs]['kernel']
        lp_mod_path = Path(rpm_dir, 'lib', 'modules', f'{kernel}-default',
                           dir_path, lp_file)
        out = subprocess.check_output(['/sbin/modinfo', str(lp_mod_path)],
                                      stderr=subprocess.STDOUT).decode()

        # Check depends field
        match = re.search('depends: (.+)', out)
        if match:
            deps = match.group(1).strip()
            # At this point we found that our livepatch module depends on
            # functions that are exported modules.

            # TODO: get the UND symbols from the livepatch and find which
            # symbols are not defined in the vmlinux. These symbols will need to
            # be worked in the livepatch.
            if deps:
                funcs = self.find_missing_symbols(cs, arch, lp_mod_path)
                print(f'WARN: {cs}:{arch} has dependencies: {deps}. Functions: {" ".join(funcs)}')

        shutil.rmtree(Path(rpm_dir, 'lib'), ignore_errors=True)

    def prepare_tests(self, skip_download):
        if not skip_download:
            # Download all built rpms
            self.download()

        config = Path(self.bsc_path, f'{self.bsc}_config.in')
        test_sh = Path(self.kgraft_tests_path,
                       f'{self.bsc}_test_script.sh')

        # Prepare the config file used by kgr-test
        self.ksrc.build()

        for arch in self.conf.get('archs', []):
            tests_path = Path(self.bsc_path, 'tests', arch)
            test_arch_path = Path(tests_path, self.bsc)

            # Remove previously created directory and archive
            shutil.rmtree(test_arch_path, ignore_errors=True)
            shutil.rmtree(f'{str(test_arch_path)}.tar.xz', ignore_errors=True)

            test_arch_path.mkdir(exist_ok=True, parents=True)

            for d in ['built', 'repro', 'tests.out']:
                Path(test_arch_path, d).mkdir(exist_ok=True)

            for cs, data in self.filter_cs(True, False).items():
                if arch not in data['archs']:
                    continue

                rpm_dir = Path(self.bsc_path, 'c', cs, arch, 'rpm')

                # TODO: there will be only one rpm, format it directly
                rpm = os.listdir(rpm_dir)
                if len(rpm) > 1:
                    raise RuntimeError(f'ERROR: {cs}/{arch}. {len(rpm)} rpms found. Excepting to find only one')

                for rpm in os.listdir(rpm_dir):
                    # Check for dependencies
                    self.validate_livepatch_module(cs, arch, rpm_dir, rpm)

                    shutil.copy(Path(rpm_dir, rpm), Path(test_arch_path, 'built'))

            shutil.copy(config, Path(test_arch_path, 'repro'))
            shutil.copy(test_sh, Path(test_arch_path, 'repro'))

            subprocess.run(['tar', '-cJf', f'{self.bsc}.tar.xz',
                                f'{self.bsc}'], cwd=tests_path,
                                        stdout=sys.stdout,
                                        stderr=subprocess.PIPE, check=True)

    def delete_rpms(self, cs):
        archs = self.codestreams[cs]['archs']
        for arch in archs:
            shutil.rmtree(Path(self.bsc_path, 'c', cs, arch, 'rpm'),
                          ignore_errors=True)

    def download(self):
        rpms = []
        for result in self.get_projects():
            prj = result.get('name')
            cs = self.convert_prj_to_cs(prj)

            # Remove previously downloaded rpms
            self.delete_rpms(cs)

            archs = result.xpath('repository/arch')
            for arch in archs:
                ret = self.osc.build.get_binary_list(prj, 'devbuild', arch, 'klp')
                rpm_name = '{}.rpm'.format(arch)
                for rpm in ret.xpath('binary/@filename'):
                    if not rpm.endswith(rpm_name):
                        continue

                    if 'preempt' in rpm:
                        continue

                    # Create a directory for each arch supported
                    dest = Path(self.bsc_path, 'c', cs, str(arch), 'rpm')
                    dest.mkdir(exist_ok=True, parents=True)

                    rpms.append( (prj, prj, 'devbuild', arch, 'klp', rpm, dest) )

        print(f'Downloading {len(rpms)} packages')
        self.do_work(self.download_binary_rpms, rpms)

    def status(self):
        prjs = {}
        for prj in self.get_project_names():
            prjs[prj] = {}

            for res in self.osc.build.get(prj).findall('result'):
                code = res.xpath('status/@code')[0]
                prjs[prj][res.get('arch')] = code

        for prj, archs in prjs.items():
            st = []
            for k, v in archs.items():
                st.append('{}: {}'.format(k, v))
            print('{}\t{}'.format(prj, '\t'.join(st)))

    def cleanup(self):
        prjs = self.get_project_names()

        if len(prjs) == 0:
            print('No projects found.')
            return

        print('Deleting {} projects...'.format(len(prjs)))

        self.do_work(self.delete_project, prjs)

    def cs_to_project(self, cs):
        return self.prj_prefix + '-' + cs.replace('.', '_')

    # Some attributes are set by default on osctiny:
    # build: enable
    # publish: disable
    def create_prj_meta(self, prj, jcs):
        prj = ET.Element('project', { 'name' : prj})

        debug = ET.SubElement(prj, 'debuginfo')
        ET.SubElement(debug, 'disable')

        ET.SubElement(prj, 'person', { 'userid' : 'mpdesouz', 'role' : 'bugowner'})

        repo = ET.SubElement(prj, 'repository', {'name' : 'devbuild'})
        ET.SubElement(repo, 'path', {'project' : jcs['project'],
                                     'repository' : jcs['repo']
                                     })

        for arch in jcs['archs']:
            ar = ET.SubElement(repo, 'arch')
            ar.text = arch

        return ET.tostring(prj).decode()

    def create_lp_package(self, cs):
        # get the kgraft branch related to this codestream
        branch = self.ksrc.get_cs_branch(cs)
        if not branch:
            raise RuntimeError(f'Could not find git branch for {cs}')

        jcs = self.codestreams[cs]

        prj = self.cs_to_project(cs)

        # If the project exists, drop it first
        self.delete_project(prj, verbose=False)

        meta = self.create_prj_meta(prj, jcs)
        prj_desc = f'Development of livepatches for {cs}'

        try:
            self.osc.projects.set_meta(prj, metafile=meta, title='',
                                       bugowner='mpdesouza',
                                       maintainer='mpdesouza',
                                       description=prj_desc)

            self.osc.packages.set_meta(prj, 'klp', title='', description='Test livepatch')

            print('\t{}: ok'.format(prj))

        except Exception as e:
            print(e, e.response.content)
            raise RuntimeError('')

        base_path = Path(self.bsc_path, 'c', cs)

        # Remove previously created directories
        prj_path = Path(base_path, 'checkout')
        if prj_path.exists():
            shutil.rmtree(prj_path)

        code_path = Path(base_path, 'code')
        if code_path.exists():
            shutil.rmtree(code_path)

        self.osc.packages.checkout(prj, 'klp', prj_path)

        # Get the code from codestream
        subprocess.check_output(['/usr/bin/git', '-C',
                                 'clone', '--single-branch', '-b', branch,
                                 str(self.kgraft_path), str(code_path)],
                                stderr=subprocess.STDOUT)

        subprocess.checkout(['./scripts/tar-up.sh', '-d', str(prj_path)],
                            stderr.subprocess.STDOUT)

        # Check how to push multiple files
        # TODO: this isn't supported by osctiny YET.

    def push(self):
        cs_list = self.apply_filter(self.codestreams.keys())

        if cs_list:
            print('Pushing projects to IBS...')

        # More threads makes OBS to return error 500
        self.do_work(self.create_lp_package, cs_list, 1)
