from pathlib import Path
from natsort import natsorted
import git
import re
import requests
import subprocess
import sys

class GitHelper:
    def __init__(self, cfg, ups_commits):
        self.cfg = cfg

        self.patched = []
        self.commits = { 'upstream' : {} }
        for commit in ups_commits:
            commit = commit[:12]
            self.commits['upstream'][commit] = self.get_commit_subject(commit)

    @staticmethod
    def build(cfg):
        build_cs = []
        repo = git.Repo(cfg.kgr_patches)

        # TODO: exclude codestreams from cfg.filter
        # TODO: call osckgr-commit.sh script

        # Filter only the branches related to this BSC
        branches = [ r.name for r in repo.branches if cfg.bsc in r.name ]

        css = cfg.codestreams

        for cs in css.keys():
            jcs = css[cs]

            entry = [ jcs['cs'],
                        jcs['project'],
                        jcs['kernel'] + '.' + jcs['build-counter'],
                        'change-me',
                        'rpm-' + jcs['kernel']
                        ]

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
        with open(Path(cfg.bsc_path, 'full_codestreams.in'), 'w') as f:
            f.write('\n'.join(build_cs))

    @staticmethod
    def verify_func_object(func, obj):
        nm_out = subprocess.check_output(['nm', obj]).decode().strip()
        return re.search(r' {}\n'.format(func), nm_out)

    def get_commit_subject(self, commit):
        req = requests.get('https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={}'.format(commit))
        req.raise_for_status()

        patches = Path(self.cfg.bsc_path, 'patches')
        patches.mkdir(exist_ok=True)

        # Save the upstream commit in the bsc directory
        fpath = Path(patches, commit + '.patch')
        with open(fpath, 'w') as f:
            f.write(req.text)

        return re.search('Subject: (.*)', req.text).group(1)

    def get_commits(self, cve_branches):
        if not self.cfg.ksrc:
            print('WARN: KLP_KERNEL_SOURCE not defined, skip getting suse commits')
            return

        print('Getting suse fixes for upstream commits per CVE branch...')

        fixes = Path(self.cfg.bsc_path, 'fixes')
        fixes.mkdir(exist_ok=True)

        # Get backported commits from the CVE branches
        for bc in cve_branches:
            patches = ''

            self.commits[bc] = {}
            for commit, _ in self.commits['upstream'].items():
                patch_file = subprocess.check_output(['/usr/bin/git', '-C',
                            str(self.cfg.ksrc),
                            'grep', '-l', 'Git-commit: ' + commit, 
                            'remotes/origin/cve/linux-' + bc],
                            stderr=subprocess.PIPE).decode(sys.stdout.encoding)

                # If we don't find any commits, add a note about it
                if not patch_file:
                    self.commits[bc]['None yet'] = ''
                    continue

                # The command above returns a string in the format
                #   branche:file/path
                branch, fpath = patch_file.strip().split(':')

                # Get the full patch in reverse order, meaning that if we have
                # follow up patches to fix any other previous patch, it will be
                # the first one listed.
                full_cmt = subprocess.check_output(['/usr/bin/git', '-C',
                            str(self.cfg.ksrc),
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
                self.commits[bc][commit] = cmt

            # Save the patch for later review from the livepatch developer
            with open(Path(fixes, bc + '.patch'), 'w') as f:
                f.write(patches)

        for key, val in self.commits['upstream'].items():
            print('{}: {}'.format(key, val))
            for cve in cve_branches:
                hash_cmt = self.commits[cve].get(key, 'None yet')
                print('\t{}\t{}'.format(cve, hash_cmt))
            print('')

    def find_patched(self, cve_branches):
        if not self.cfg.ksrc:
            print('WARN: KLP_KERNEL_SOURCE not defined, skip getting suse commits')
            return

        print('Searching for already patched codestreams...')

        patched = []
        for branch in cve_branches:
            for up_commit, suse_commit in self.commits[branch].items():
                tags = subprocess.check_output(['/usr/bin/git', '-C',
                            str(self.cfg.ksrc), 'tag', '--contains=' + suse_commit])

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
        self.patched = natsorted(list(set(patched)))
