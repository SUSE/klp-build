import logging
from pathlib import Path
import os
import shutil
import unittest
from unittest.mock import patch

import sys
sys.path.append('..')
from lp_setup import Setup

class LpSetupTest(unittest.TestCase):
    def setUp(self):
        # Default arguments of Setup
        self.d = {
            'bsc' : '9999999',
            'filter' : '',
            'cve' : '1234-5678',
            'cs' : '',
            'file_funcs' : [],
            'mod_file_funcs' : [],
            'conf_mod_file_funcs' : [],
            'module' : 'vmlinux',
            'conf' : '',
            'archs': []
        }

        # To be used later before calling setup, erasing any previously created
        # project
        self.basedir = Path(os.getenv('KLP_WORK_DIR', ''), 'bsc9999999')

        # Avoid searching for patches kernels
        os.environ['KLP_KERNEL_SOURCE'] = ''

        logging.disable(logging.INFO)

    def setup(self, dargs):
        shutil.rmtree(self.basedir, ignore_errors=True)

        with self.assertNoLogs(level='WARNING') as anl:
            return Setup(*tuple(dargs.values()))

    def setup_assert_logs(self, dargs, alevel, msg):
        shutil.rmtree(self.basedir, ignore_errors=True)

        with self.assertLogs(level=alevel) as logs:
            s = Setup(*tuple(dargs.values()))
            s.setup_project_files()

        self.assertRegex(logs.output[0], msg)

    def setup_and_assert(self, dargs, exc, msg = None):
        shutil.rmtree(self.basedir, ignore_errors=True)

        with self.assertRaises(exc) as ar:
            s = Setup(*tuple(dargs.values()))
            return s.setup_project_files()

        if not msg:
            self.assertEqual(str(ar.exception), msg)

    def test_missing_conf_archs(self):
        v = self.d.copy()
        self.setup_and_assert(v, ValueError,
                'Please specify --conf when not all architectures are supported')

        # All archs supported, complain about file-funcs
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        self.setup_and_assert(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

        # Only one arch supported, but conf informed, complain about file-funcs
        v['archs'] = ['x86_64']
        v['conf'] = 'CONFIG_TUN'
        self.setup_and_assert(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

    def test_missing_conf_mod(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        self.setup_and_assert(v, ValueError,
                'Please specify --conf when a module is specified')

        # if module is vmlinux it should only complains about file-funcs
        v['module'] = 'vmlinux'
        self.setup_and_assert(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

    def test_missing_file_funcs(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        self.setup_and_assert(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

    def test_file_funcs_ok(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = ['drivers/net/tun.c', 'tun_chr_ioctl', 'tun_free_netdev']
        self.setup(v)

        # Checks if the variants of file-funcs also work
        v['file_funcs'] = []
        v['mod_file_funcs'] = [['tun', 'drivers/net/tun.c', 'tun_chr_ioctl',
                                'tun_free_netdev']]
        self.setup(v)

        v['mod_file_funcs'] = []
        v['conf_mod_file_funcs'] = [['CONFIG_TUN', 'tun', 'drivers/net/tun.c',
                                     'tun_chr_ioctl', 'tun_free_netdev']]
        self.setup(v)

    def test_non_existent_file(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tuna.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]

        self.setup_and_assert(v, RuntimeError, 'File drivers/net/tuna.c not found')

    def test_existent_file(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tun.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]
        s = self.setup(v)
        s.setup_project_files()

    def test_invalid_sym(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tun.c', 'tun_chr_ioctll',
                            'tun_free_netdev']]

        self.setup_assert_logs(v, 'WARNING',
                'Function drivers/net/tun.c:tun_chr_ioctll doesn\'t exist in '
                'kernel/drivers/net/tun.ko')

    def test_non_existent_module(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tuna'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tun.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]

        self.setup_and_assert(v, RuntimeError, 'Module not found: tuna')

    def test_check_symbol_addr_s390(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['filter'] = '12.4u35'
        v['module'] = 'sch_qfq'
        v['conf'] = 'CONFIG_NET_SCH_QFQ'
        v['file_funcs'] = [['net/sched/sch_qfq.c', 'qfq_change_class']]
        s = self.setup(v)
        s.setup_project_files()

        # The address of qfq_policy on s390x ends with a character, a bug that
        # was fixed by checking for \w instead of \d.
        # With the fix in place, check_symbol_archs should return an empty list
        self.assertFalse(s.check_symbol_archs('12.4u35', 'qfq_policy',
                                              'sch_qfq'))

if __name__ == '__main__':
    unittest.main()