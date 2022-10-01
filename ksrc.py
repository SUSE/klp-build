from config import Config
from natsort import natsorted
import git
from pathlib import Path
import os
import re
import requests
import subprocess
import sys

class GitHelper(Config):
    def __init__(self, bsc, bsc_filter):
        super().__init__(bsc, bsc_filter)

        self.kern_src = os.getenv('KLP_KERNEL_SOURCE', '')
        if self.kern_src and not Path(self.kern_src).is_dir():
            raise ValueError('KLP_KERNEL_SOURCE should point to a directory')

        self.kgr_patches = Path(Path().home(), 'kgr', 'kgraft-patches')
        if not self.kgr_patches.is_dir():
            raise RuntimeError('kgraft-patches does not exists in ~/kgr')

        self.kernel_branches = {
                                '4.12' : 'cve/linux-4.12',
                                '5.3' : 'cve/linux-5.3',
                                '5.14' : 'SLE15-SP4'
                            }

    def build(self):
        build_cs = []
        repo = git.Repo(self.kgr_patches)

        # TODO: call osckgr-commit.sh script

        # Filter only the branches related to this BSC
        branches = [ r.name for r in repo.branches if self.bsc in r.name ]

        for cs, data in self.filtered_cs().items():
            jcs = data

            entry = [ jcs['cs'],
                        jcs['project'],
                        jcs['kernel'] + '.' + jcs['build-counter'],
                        'change-me',
                        'rpm-' + jcs['kernel']
                        ]

            for branch in branches:
                # First check if the branch has more than code stream sharing
                # the same code
                for b in branch.replace(self.bsc + '_', '').split('_'):
                    sle, u = b.split('u')
                    if sle != f"{jcs['sle']}.{jcs['sp']}":
                        continue

                    # Get codestreams interval
                    up = u
                    down = u
                    cs_update = jcs['update']
                    if '-' in u:
                        down, up = u.split('-')

                    # Codestream between the branch codestream interval
                    if int(cs_update) >= int(down) and int(cs_update) <= int(up):
                        # replace the 'change-me' string in entry
                        entry[3] = branch

                    # At this point we found a match for our codestream in
                    # codestreams.json, but we may have a more specialized git
                    # branch later one, like:
                    # bsc1197597_12.4u21-25_15.0u25-28
                    # bsc1197597_15.0u25-28
                    # Since 15.0 SLE uses a different kgraft-patches branch to
                    # be built on. In this case, we continue to loop over the
                    # other branches.

            # If there was a match in all available branches
            if entry[3] != 'change-me':
                build_cs.append(','.join(entry))

        # Save file to be used later by osckgr scripts
        with open(Path(self.bsc_path, f'{self.bsc}_config.in'), 'w') as f:
            f.write('\n'.join(build_cs))

    def get_cs_branch(self, cs):
        sle, sp, up = self.get_cs_tuple(cs)
        repo = git.Repo(self.kgr_patches)

        all_branches = git.Repo(self.kgr_patches).branches

        # Filter only the branches related to this BSC
        branches = [ b for b in all_branches if self.bsc in b ]
        branch_name = ''

        for branch in branches:
            # First check if the branch has more than code stream sharing
            # the same code
            for b in branch.replace(self.bsc + '_', '').split('_'):
                sle, u = b.split('u')
                if sle != f'{sle}.{sp}':
                    continue

                # Get codestreams interval
                up = u
                down = u
                cs_update = up
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

    def format_patches(self):
        repo = git.Repo(self.kgr_patches)

        # Filter only the branches related to this BSC
        branches = [ r.name for r in repo.branches if self.bsc in r.name ]

        for branch in branches:
            print(branch)
            bname = branch.replace(self.bsc + '_', '')
            bs = ' '.join(bname.split('_'))
            bsc = self.bsc.replace('bsc', 'bsc#')

            subprocess.check_output(['/usr/bin/git', '-C', str(self.kgr_patches),
                            'format-patch', '-1', branch,
                            f'--subject-prefix=PATCH v2 {bsc} {bs}', '--output',
                                     f'{bname}.patch'])

    def get_commit_subject(self, commit):
        req = requests.get('https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={}'.format(commit))
        req.raise_for_status()

        patches = Path(self.bsc_path, 'patches')
        patches.mkdir(exist_ok=True)

        # Save the upstream commit in the bsc directory
        fpath = Path(patches, commit + '.patch')
        with open(fpath, 'w') as f:
            f.write(req.text)

        return re.search('Subject: (.*)', req.text).group(1)

    def get_commits(self, ups_commits):
        if not self.kern_src:
            print('WARN: KLP_KERNEL_SOURCE not defined, skip getting suse commits')
            return

        # do not get the commits twice
        if self.conf.get('commits', ''):
            return self.conf['commits']

        print('Getting suse fixes for upstream commits per CVE branch...')

        commits = { 'upstream' : {} }
        for commit in ups_commits:
            commit = commit[:12]
            commits['upstream'][commit] = self.get_commit_subject(commit)

        fixes = Path(self.bsc_path, 'fixes')
        fixes.mkdir(exist_ok=True)

        # Get backported commits from the CVE branches
        for bc, mbranch in self.kernel_branches.items():
            patches = ''

            commits[bc] = {}
            for commit, _ in commits['upstream'].items():
                try:
                    patch_file = subprocess.check_output(['/usr/bin/git', '-C',
                                self.kern_src,
                                'grep', '-l', f'Git-commit: {commit}',
                                f'remotes/origin/{mbranch}'],
                                stderr=subprocess.STDOUT).decode(sys.stdout.encoding)
                except subprocess.CalledProcessError:
                    patch_file = ''

                # If we don't find any commits, add a note about it
                if not patch_file:
                    commits[bc]['None yet'] = ''
                    continue

                # The command above returns a string in the format
                #   branche:file/path
                branch, fpath = patch_file.strip().split(':')

                # Get the full patch in reverse order, meaning that if we have
                # follow up patches to fix any other previous patch, it will be
                # the first one listed.
                full_cmt = subprocess.check_output(['/usr/bin/git', '-C',
                            self.kern_src,
                            'log', '--reverse', '--patch', branch, '--', fpath],
                            stderr=subprocess.PIPE).decode(sys.stdout.encoding)

                m = re.search('commit (\w+)', full_cmt)
                if not m:
                    raise RuntimeError('Commit hash not found in patch:\n{}' \
                            .format(full_cmt))

                commit_hash = m.group(1)

                patches = patches + full_cmt

                cmt = commit_hash.strip().replace('"', '')

                # Link the upstream commit as key asn the suse commit as value
                commits[bc][commit] = cmt

            # Check if the commit was backport/present in the supported kernel
            # family
            if patches:
                # Save the patch for later review from the livepatch developer
                with open(Path(fixes, bc + '.patch'), 'w') as f:
                    f.write(patches)

        for key, val in commits['upstream'].items():
            print('{}: {}'.format(key, val))
            for bc, _ in self.kernel_branches.items():
                hash_cmt = commits[bc].get(key, 'None yet')
                print('\t{}\t{}'.format(bc, hash_cmt))
            print('')

        return commits

    def get_patched_cs(self, commits):
        if not self.kern_src:
            print('WARN: KLP_KERNEL_SOURCE not defined, skip getting suse commits')
            return

        # do not get the commits twice
        patched = self.conf.get('patched', [])
        if patched:
            return patched

        print('Searching for already patched codestreams...')

        patched = []
        for bc, branch in self.kernel_branches.items():
            for up_commit, suse_commit in commits[bc].items():
                if suse_commit == '':
                    continue

                tags = subprocess.check_output(['/usr/bin/git', '-C',
                            self.kern_src, 'tag', f'--contains={suse_commit}'])

                for tag in tags.decode().splitlines():
                    tag = tag.strip()
                    if not tag.startswith('rpm-'):
                        continue

                    # Remove noise around the kernel version, like
                    # rpm-5.3.18-150200.24.112--sle15-sp2-ltss-updates
                    tag = tag.replace('rpm-', '')
                    tag = re.sub('--.*', '', tag)

                    patched.append(tag)

        # remove duplicates
        patched = natsorted(list(set(patched)))

        css = []
        # Find which codestreams are related to each patched kernel
        for cs in self.codestreams.keys():
            if self.codestreams[cs]['kernel'] in patched:
                css.append(cs)

        return css
