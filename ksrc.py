import os
from pathlib import Path
import re
import requests
import subprocess
import sys

class GitHelper:
    def __init__(self, cfg, ups_commits):
        self.cfg = cfg

        self.commits = { 'upstream' : {} }
        for commit in ups_commits:
            commit = commit[:12]
            self.commits['upstream'][commit] = self.get_commit_subject(commit)

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

        # Get backported commits from the CVE branches
        for bc in cve_branches:
            cved = Path(self.cfg.bsc_path, 'fixes', bc)

            cved.mkdir(exist_ok=True, parents=True)

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

                # Save the patch for later review from the livepatch developer
                with open(Path(cved, commit_hash + '.patch'), 'w') as f:
                    f.write(full_cmt)

                cmt = commit_hash.strip().replace('"', '')

                # Link the upstream commit as key asn the suse commit as value
                self.commits[bc][commit] = cmt

        for key, val in self.commits['upstream'].items():
            print('{}: {}'.format(key, val))
            for cve in cve_branches:
                hash_cmt = self.commits[cve].get(key, 'None yet')
                print('\t{}\t{}'.format(cve, hash_cmt))
            print('')
