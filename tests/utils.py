import os
from pathlib import Path
import shutil
import sys
import unittest

sys.path.append('..')
from lp_setup import Setup

class TestUtils(unittest.TestCase):

    # default setup args
    def sargs(self):
        return {
            'bsc' : '9999999',
            'filter' : '',
            'cve' : '1234-5678',
            'cs' : '',
            'file_funcs' : [],
            'mod_file_funcs' : [],
            'conf_mod_file_funcs' : [],
            'module' : 'vmlinux',
            'conf' : '',
            'archs': ['x86_64', 'ppc64le', 's390x']
        }

    def basedir(self, v):
        return Path(os.getenv('KLP_WORK_DIR', ''), f'bsc{v["bsc"]}')

    def lpdir(self, v, cs):
        return Path(os.getenv('KLP_WORK_DIR', ''), f'bsc{v["bsc"]}', 'c', cs,
        'lp')

    def setup(self, dargs, init = False):
        shutil.rmtree(self.basedir(dargs), ignore_errors=True)

        s = Setup(*tuple(dargs.values()))
        if init:
            s.setup_project_files()

        return s

    def setup_nologs(self, dargs, init = False):
        with self.assertNoLogs(level='WARNING'):
            return self.setup(dargs, init)

    def setup_assert_logs(self, dargs, alevel, msg):
        with self.assertLogs(level=alevel) as logs:
            self.setup(dargs, True)

        self.assertRegex(logs.output[0], msg)

    def setup_and_assert(self, dargs, exc, msg = None):
        with self.assertRaises(exc) as ar:
            self.setup(dargs, True)

        if not msg:
            self.assertEqual(str(ar.exception), msg)

    def get_file_content(self, v, cs, fname=None):
        # Check the generated LP files
        path = self.lpdir(v, cs)

        if not fname:
            fname = f'livepatch_bsc{v["bsc"]}.c'

        with open(Path(path, fname)) as f:
            return f.read()

    def output_contains(self, v, cs, msgs, fname=None):
        buf = self.get_file_content(v, cs, fname)
        for msg in msgs:
            self.assertTrue(msg in buf)

    def output_contains_not(self, v, cs, msgs, fname=None):
        buf = self.get_file_content(v, cs, fname)
        for msg in msgs:
            self.assertTrue(msg not in buf)
