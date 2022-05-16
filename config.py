import json
import git
from pathlib import Path
import os
import re

class Config:
    def __init__(self, args):
        self.filter = args.filter

        # Prefer the argument over the environment
        work_dir = args.work_dir
        if not work_dir:
            work_dir = os.getenv('KLP_WORK_DIR')
            if not work_dir:
                raise ValueError('--work-dir or KLP_WORK_DIR should be defined')

        self.work = Path(work_dir)
        if not self.work.is_dir():
            raise ValueError('Work dir should be a directory')

        bsc = args.bsc
        self.bsc_num = bsc
        self.bsc = 'bsc' + str(bsc)
        self.bsc_path = Path(self.work, self.bsc)

        # We'll create the directory on setup, so we require it to now exists
        if args.cmd == 'setup':
            if self.bsc_path.exists() and not self.bsc_path.is_dir():
                raise ValueError('--bsc needs to be a directory, or not to exist')

            # We only require --data for setup, since conf.json will contain all
            # relevant data for the later steps
            data = args.data
            # Prefer the argument over the environment
            if not data:
                data = os.getenv('KLP_DATA_DIR', '')
                if not data:
                    raise ValueError('--data or KLP_DATA_DIR should be defined')

            self.data = Path(data)
            if not self.data.is_dir():
                raise ValueError('Data dir should be a directory')

        self.ksrc = os.getenv('KLP_KERNEL_SOURCE')
        if self.ksrc and not Path(self.ksrc).is_dir():
            raise ValueError('KLP_KERNEL_SOURCE should point to a directory')

        if args.cmd == 'get-patches' and not self.ksrc:
            raise ValueError('KLP_KERNEL_SOURCE should be defined')

        self.codestreams = {}
        self.cs_file = Path(self.bsc_path, 'codestreams.json')
        if self.cs_file.is_file():
            with open(self.cs_file, 'r') as f:
                self.codestreams = json.loads(f.read())


        self.conf = {}
        self.conf_file = Path(self.bsc_path, 'conf.json')
        if self.conf_file.is_file():
            with open(self.conf_file, 'r') as f:
                self.conf = json.loads(f.read())

        # run-ccp and create-lp commands only work if codestreams.json and
        # conf.json files exist
        if args.cmd in ['run-ccp', 'create-lp']:
            if not self.codestreams:
                raise ValueError('codestreams.json file not found.')
            if not self.conf:
                raise ValueError('conf.json file not found.')

        try:
            git_data = git.GitConfigParser()
            self.user = git_data.get_value('user', 'name')
            self.email = git_data.get_value('user', 'email')
        except:
            raise ValueError('Please define name/email in global git config')

        self.bsc_path.mkdir(exist_ok=True)
