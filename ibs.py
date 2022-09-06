import concurrent.futures
import errno
from lxml import etree
import git
from pathlib import Path
import os
from osctiny import Osc
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

class IBS:
    def __init__(self, cfg):
        self.cfg = cfg
        self.osc = Osc(url='https://api.suse.de')

        self.ibs_user = re.search('(\w+)@', cfg.email).group(1)
        self.prj_prefix = 'home:{}:klp'.format(self.ibs_user)

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
                    'kernel-default' : '(kernel-default\-(extra|(livepatch-devel|kgraft)?\-?devel)?\-?[\d\.\-]+.x86_64.rpm)',
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
        return self.osc.search.project("starts-with(@name, '{}')".format(self.prj_prefix))

    def get_project_names(self):
        names = []
        for result in self.get_projects().findall('project'):
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

        fcs = self.cfg.codestreams[cs]['cs']
        kernel = self.cfg.codestreams[cs]['kernel']

        if 'livepatch' in rpm or 'kgraft-devel' in rpm:
            path_dest = Path(self.cfg.ipa_dir, fcs, arch)
        elif re.search('kernel\-default\-\d+', rpm) or \
                re.search('kernel\-default\-devel\-\d+', rpm):
            path_dest = Path(self.cfg.ex_dir, fcs, arch)
        else:
            path_dest = Path(self.cfg.ex_dir, fcs)

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

        # TODO: extract all compressed files

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
            jcs = self.cfg.codestreams[cs]
            prj = jcs['project']
            repo = jcs['repo']

            path_dest = Path(self.cfg.kernel_rpms, jcs['cs'])
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

    def apply_filter(self, item_list):
        if not self.cfg.filter:
            return item_list

        filtered = []
        for item in item_list:
            if not re.match(self.cfg.filter, item.replace('_', '.')):
                continue

            filtered.append(item)

        return filtered

    def download(self):
        rpms = []
        for result in self.get_projects().findall('project'):
            prj = result.get('name')

            if self.cfg.filter and not re.match(self.cfg.filter, prj):
                continue

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
                    dest = Path(self.cfg.bsc_download, str(arch))
                    dest.mkdir(exist_ok=True)

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
            return

        print('{} projects found.'.format(len(prjs)))

        prjs = self.apply_filter(prjs)

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

    def get_cs_branch(self, cs):
        jcs = self.cfg.codestreams[cs]
        repo = git.Repo(self.cfg.kgr_patches)

        all_branches = git.Repo(cfg.kgr_patches).branches

        # Filter only the branches related to this BSC
        branches = [ b for b in all_branches if self.cfg.bsc in b ]
        branch_name = ''

        for branch in branches:
            # First check if the branch has more than code stream sharing
            # the same code
            for b in branch.replace(cfg.bsc + '_', '').split('_'):
                sle, u = b.split('u')
                if sle != jcs['sle'] + '.' + jcs['sp']:
                    continue

                # Get codestreams interval
                up = u
                down = u
                cs_update = int(jcs['update'])
                if '-' in u:
                    down, up = u.split('-')

                # Codestream between the branch codestream interval
                if cs_update >= int(down) and cs_update <= int(up):
                    branch_name = branch
                    break

                # At this point we found a match for our codestream in
                # codestreams.json, but we may have a more specialized git
                # branch later one, like:
                # bsc1197597_12.4u21-25_15.0u25-28
                # bsc1197597_15.0u25-28
                # Since 15.0 SLE uses a different kgraft-patches branch to
                # be built on. In this case, we continue to loop over the
                # other branches.

        return branch_name

    def create_lp_package(self, cs):

        # get the kgraft branch related to this codestream
        branch = self.get_cs_branch(cs)
        if not branch:
            raise RuntimeError(f'Could not find git branch for {cs}')

        jcs = self.cfg.codestreams[cs]

        prj = self.cs_to_project(cs)

        # If the project exists, drop it first
        self.delete_project(prj, verbose=False)

        meta = self.create_prj_meta(prj, jcs)
        prj_desc = 'Development of livepatches for SLE{}-SP{} Update {}' \
                .format(jcs['sle'], jcs['sp'], jcs['update'])

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

        base_path = Path(self.cfg.bsc_path, 'c', cs)

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
                                 str(self.cfg.kgraft_path), str(code_path)],
                                stderr=subprocess.STDOUT)

        subprocess.checkout(['./scripts/tar-up.sh', '-d', str(prj_path)],
                            stderr.subprocess.STDOUT)

        # Check how to push multiple files
        # TODO: this isn't supported by osctiny YET.

    def push(self):
        cs_list = self.apply_filter(self.cfg.codestreams.keys())

        if cs_list:
            print('Pushing projects to IBS...')

        # More threads makes OBS to return error 500
        self.do_work(self.create_lp_package, cs_list, 1)
