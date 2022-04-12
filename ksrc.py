import os
from pathlib import Path
import re
import subprocess
import sys

class GitHelper:
    def __init__(self, cfg):
        self.cfg = cfg

    def get_commits(self, cve_branches, commits):
        if not self.cfg.ksrc:
            print('WARN: KLP_KERNEL_SOURCE not defined, skip getting suse commits')
            return

        print('Getting suse fixes for upstream commits per CVE branch...')

        # Get backported commits from the CVE branches
        for bc in cve_branches:

            cved = Path(self.cfg.bsc_path, 'fixes', bc)

            cved.mkdir(exist_ok=True, parents=True)

            commits[bc] = {}
            for commit, _ in commits['upstream'].items():
                patch_file = subprocess.check_output(['/usr/bin/git', '-C',
                            str(self.cfg.ksrc),
                            'grep', '-l', 'Git-commit: ' + commit, 
                            'remotes/origin/cve/linux-' + bc],
                            stderr=subprocess.PIPE).decode(sys.stdout.encoding)

                # If we don't find any commits, add a note about it
                if not patch_file:
                    commits[bc]['None yet'] = ''
                    continue

                # The command above returns a string in the format
                #   branche:file/path
                branch, fpath = patch_file.strip().split(':')

                # Get the full patch
                cmt = subprocess.check_output(['/usr/bin/git', '-C',
                            str(self.cfg.ksrc),
                            'log', '--patch', branch, fpath],
                            stderr=subprocess.PIPE).decode(sys.stdout.encoding)

                m = re.search('commit (\w+)', cmt)
                if not m:
                    raise RuntimeError('Commit hash not found in patch:\n{}' \
                            .format(cmt))

                commit_hash = m.group(1)

                # Save the patch for later review from the livepatch developer
                with open(Path(cved, commit_hash + '.patch'), 'w') as f:
                    f.write(cmt)

                cmt = commit_hash.strip().replace('"', '')

                # Link the upstream commit as key asn the suse commit as value
                commits[bc][commit] = cmt

        for key, val in commits['upstream'].items():
            print('{}: {}'.format(key, val))
            for cve in cve_branches:
                hash_cmt = commits[cve].get(key, 'None yet')
                print('\t{}\t{}'.format(cve, hash_cmt))
            print('')
