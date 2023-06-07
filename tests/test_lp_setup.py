from pathlib import Path
import os
import shutil
import unittest

import sys
sys.path.append('..')
from lp_setup import Setup

#--module tls --conf CONFIG_TLS --file-funcs net/tls/tls_main.c do_tls_getsockopt_conf --archs x86_64

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

        # Erase any previously created test
        basedir = Path(os.getenv('KLP_WORK_DIR', ''), 'bsc9999999')
        shutil.rmtree(basedir, ignore_errors=True)

        # Avoid searching for patches kernels
        os.environ['KLP_KERNEL_SOURCE'] = ''

    def exec_assert_check_msg(self, dargs, exc, msg):
        targs = tuple(dargs.values())
        with self.assertRaises(exc) as ar:
            # The * operator expands the tuple into the argument of the
            # constructor
            Setup(*targs)

        self.assertEqual(str(ar.exception), msg)

    def ok(self, dargs):
        return Setup(*tuple(dargs.values()))

    def test_missing_conf_archs(self):
        v = self.d.copy()
        self.exec_assert_check_msg(v, ValueError,
                'Please specify --conf when not all architectures are supported')

        # All archs supported, complain about file-funcs
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        self.exec_assert_check_msg(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

        # Only one arch supported, but conf informed, complain about file-funcs
        v['archs'] = ['x86_64']
        v['conf'] = 'CONFIG_TUN'
        self.exec_assert_check_msg(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

    def test_missing_conf_mod(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        self.exec_assert_check_msg(v, ValueError,
                'Please specify --conf when a module is specified')

        # if module is vmlinux it should only complains about file-funcs
        v['module'] = 'vmlinux'
        self.exec_assert_check_msg(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

    def test_missing_file_funcs(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        self.exec_assert_check_msg(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

    def test_file_funcs_ok(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = ['drivers/net/tun.c', 'tun_chr_ioctl', 'tun_free_netdev']
        self.ok(v)

        # Checks if the variants of file-funcs also work
        v['file_funcs'] = []
        v['mod_file_funcs'] = [['tun', 'drivers/net/tun.c', 'tun_chr_ioctl',
                                'tun_free_netdev']]
        self.ok(v)

        v['mod_file_funcs'] = []
        v['conf_mod_file_funcs'] = [['CONFIG_TUN', 'tun', 'drivers/net/tun.c',
                                     'tun_chr_ioctl', 'tun_free_netdev']]
        self.ok(v)

    def test_non_existent_file(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tuna.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]
        s = self.ok(v)

        with self.assertRaises(RuntimeError) as ar:
            s.setup_project_files()

        self.assertRegex(str(ar.exception), 'File drivers/net/tuna.c not found')

    def test_existent_file(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tun.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]
        s = self.ok(v)
        s.setup_project_files()

    def test_non_existent_module(self):
        v = self.d.copy()
        v['archs'] = ['x86_64', 'ppc64le', 's390x']
        v['module'] = 'tuna'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tun.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]
        s = self.ok(v)

        with self.assertRaises(RuntimeError) as ar:
            s.setup_project_files()

        self.assertRegex(str(ar.exception), 'Module not found: tuna')

if __name__ == '__main__':
    unittest.main()
