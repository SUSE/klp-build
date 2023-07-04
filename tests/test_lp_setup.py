import json
import logging
from pathlib import Path
import os
import sys
import unittest

from tests import utils

sys.path.append('..')

class LpSetupTest(utils.TestUtils):
    def setUp(self):
        # Avoid searching for patches kernels
        os.environ['KLP_KERNEL_SOURCE'] = ''

        logging.disable(logging.INFO)

    def test_missing_conf_archs(self):
        v = self.sargs()
        v['archs'] = []
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
        v = self.sargs()
        v['module'] = 'tun'
        self.setup_and_assert(v, ValueError,
                'Please specify --conf when a module is specified')

        # if module is vmlinux it should only complains about file-funcs
        v['module'] = 'vmlinux'
        self.setup_and_assert(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

    def test_missing_conf_prefix(self):
        v = self.sargs()
        v['module'] = 'tun'
        v['conf'] = 'TUN'
        self.setup_and_assert(v, ValueError, 'Please specify --conf with CONFIG_ prefix')

    def test_missing_file_funcs(self):
        v = self.sargs()
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        self.setup_and_assert(v, ValueError,
                'You need to specify at least one of the file-funcs variants!')

    def test_file_funcs_ok(self):
        v = self.sargs()
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = ['drivers/net/tun.c', 'tun_chr_ioctl', 'tun_free_netdev']
        self.setup_nologs(v)

        # Checks if the variants of file-funcs also work
        v['file_funcs'] = []
        v['mod_file_funcs'] = [['tun', 'drivers/net/tun.c', 'tun_chr_ioctl',
                                'tun_free_netdev']]
        self.setup_nologs(v)

        v['mod_file_funcs'] = []
        v['conf_mod_file_funcs'] = [['CONFIG_TUN', 'tun', 'drivers/net/tun.c',
                                     'tun_chr_ioctl', 'tun_free_netdev']]
        self.setup_nologs(v)

    def test_non_existent_file(self):
        v = self.sargs()
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tuna.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]

        self.setup_and_assert(v, RuntimeError, 'File drivers/net/tuna.c not found')

    def test_existent_file(self):
        v = self.sargs()
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tun.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]
        self.setup_nologs(v, True)

    def test_invalid_sym(self):
        v = self.sargs()
        v['module'] = 'tun'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tun.c', 'tun_chr_ioctll',
                            'tun_free_netdev']]

        self.setup_assert_logs(v, 'WARNING',
                'Symbols tun_chr_ioctll not found on tun')

    def test_non_existent_module(self):
        v = self.sargs()
        v['module'] = 'tuna'
        v['conf'] = 'CONFIG_TUN'
        v['file_funcs'] = [['drivers/net/tun.c', 'tun_chr_ioctl',
                            'tun_free_netdev']]

        self.setup_and_assert(v, RuntimeError, 'Module not found: tuna')

    def test_check_symbol_addr_s390(self):
        v = self.sargs()
        cs = '12.5u44'
        v['filter'] = cs
        v['module'] = 'sch_qfq'
        v['conf'] = 'CONFIG_NET_SCH_QFQ'
        v['file_funcs'] = [['net/sched/sch_qfq.c', 'qfq_change_class']]
        s = self.setup_nologs(v, True)

        # The address of qfq_policy on s390x ends with a character, a bug that
        # was fixed by checking for \w instead of \d.
        # With the fix in place, check_symbol_archs should return an empty list
        self.assertFalse(s.check_symbol_archs(cs, 'sch_qfq', ['qfq_policy']))

    def test_check_conf_mod_file_funcs(self):
        v = self.sargs()
        cs = '15.4u12'
        v['archs'] = ['x86_64']
        v['filter'] = cs
        v['module'] = 'sch_qfq'
        v['conf'] = 'CONFIG_NET_SCH_QFQ'
        v['file_funcs'] = [['net/sched/sch_qfq.c', 'qfq_change_class']]
        v['mod_file_funcs'] = [[ 'btsdio',
                                 'drivers/bluetooth/btsdio.c',
                                 'btsdio_probe', 'btsdio_remove' ]]

        # CONF should be same, but mod doesn't
        self.setup_nologs(v, True)

        with open(Path(self.basedir(v), 'codestreams.json')) as f:
            data = json.loads(f.read())[cs]['files']

        sch = data['net/sched/sch_qfq.c']
        bts = data['drivers/bluetooth/btsdio.c']
        self.assertEqual(sch['conf'], bts['conf'])
        self.assertEqual(sch['module'], 'sch_qfq')
        self.assertEqual(bts['module'], 'btsdio')

        v['conf_mod_file_funcs'] = [[ 'CONFIG_BT_HCIBTSDIO',
                                     'btsdio',
                                     'drivers/bluetooth/btsdio.c',
                                     'btsdio_probe', 'btsdio_remove' ]]

        # Now, conf and module should be different
        s = self.setup_nologs(v, True)

        with open(Path(self.basedir(v), 'codestreams.json')) as f:
            data = json.loads(f.read())[cs]['files']

        sch = data['net/sched/sch_qfq.c']
        bts = data['drivers/bluetooth/btsdio.c']
        self.assertEqual(sch['conf'], 'CONFIG_NET_SCH_QFQ')
        self.assertEqual(sch['module'], 'sch_qfq')
        self.assertEqual(bts['conf'], 'CONFIG_BT_HCIBTSDIO')
        self.assertEqual(bts['module'], 'btsdio')

if __name__ == '__main__':
    unittest.main()
