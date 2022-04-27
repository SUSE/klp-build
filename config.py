from pathlib import Path
import os
import re

class Config:
    def __init__(self, args):
        work_dir = args.work_dir
        bsc = args.bsc
        self.filter = args.filter

        # We only require --data for setup, since conf.json will contain all
        # relevant data for the later steps
        if args.cmd == 'setup':
            data = args.data
            # Prefer the argument over the environment
            if not data:
                data = os.getenv('KLP_DATA_DIR')
                if not data:
                    raise ValueError('--data or KLP_DATA_DIR should be defined')

            self.env = Path(data)
            if not self.env.is_dir():
                raise ValueError('Data dir should be a directory')

        # Prefer the argument over the environment
        if not work_dir:
            work_dir = os.getenv('KLP_WORK_DIR')
            if not work_dir:
                raise ValueError('--work-dir or KLP_WORK_DIR should be defined')

        self.work = Path(work_dir)
        if not self.work.is_dir():
            raise ValueError('Work dir should be a directory')

        self.bsc_num = bsc
        self.bsc = 'bsc' + str(bsc)
        self.bsc_path = Path(self.work, self.bsc)

        # We'll create the directory on setup, so we require it to now exists
        if args.cmd == 'setup':
            if self.bsc_path.exists() and not self.bsc_path.is_dir():
                raise ValueError('--bsc needs to be a directory, or not to exist')

        self.ksrc = os.getenv('KLP_KERNEL_SOURCE')
        if self.ksrc and not Path(self.ksrc).is_dir():
            raise ValueError('KLP_KERNEL_SOURCE should point to a directory')

        if args.cmd == 'get-patches' and not self.ksrc:
            raise ValueError('KLP_KERNEL_SOURCE should be defined')

        self.bsc_path.mkdir(exist_ok=True)
