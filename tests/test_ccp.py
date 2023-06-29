from pathlib import Path
import logging
import os
import unittest
import sys

sys.path.append('..')
from ccp import CCP

from tests import utils

class CcpTesting(utils.TestUtils):
    def setUp(self):
        os.environ['KLP_KERNEL_SOURCE'] = ''

        logging.disable(logging.INFO)

    def test_detect_file_without_ftrace_support(self):
        v = self.sargs()
        cs = '15.3u32'
        v['filter'] = cs
        v['module'] = 'vmlinux'
        v['file_funcs'] = [['lib/seq_buf.c', 'seq_buf_putmem_hex']]

        with self.assertLogs(level='WARNING') as logs:
            self.setup(v, True)
            ccp = CCP(v['bsc'], cs, [])
            ccp.run_ccp()

        self.assertRegex(logs.output[0],
            'lib/seq_buf.o is not compiled with livepatch support \(\-pg flag\)')

        # Check the generated LP files
        path = self.lpdir(v, cs)
        with open(Path(path, 'livepatch_bsc9999999.c')) as f:
            buf = f.read()

        # As we passed vmlinux as module, we don't have the module notifier and
        # LP_MODULE, linux/module.h is not included
        # As the code is using the default archs, which is all of them, the
        # IS_ENABLED macro shouldn't exist
        self.output_contains_not(buf, ['LP_MODULE', 'module_notify',
                                       'linux/module.h', '#if IS_ENABLED'
                                       ])

        # For this file and symbol, there is one symbol to be looked up, so
        # klp_funcs should be present
        self.output_contains(buf, ['klp_funcs'])

    def test_lp_file_klp_funcs_out(self):
        v = self.sargs()
        cs = '15.5u0'
        v['filter'] = cs
        v['module'] = 'vmlinux'
        v['file_funcs'] = [['net/ipv6/rpl.c', 'ipv6_rpl_srh_size']]
        v['conf'] = 'CONFIG_IPV6'
        v['archs'] = ['x86_64']

        self.setup_nologs(v, True)
        ccp = CCP(v['bsc'], cs, [])
        ccp.run_ccp()

        # Check the generated LP files
        path = self.lpdir(v, cs)
        with open(Path(path, 'livepatch_bsc9999999.c')) as f:
            buf = f.read()

        # As we passed vmlinux as module, we don't have the module notifier and
        # LP_MODULE, linux/module.h is not included
        # For this file and symbol, no externalized symbols are used, so
        # klp_funcs shouldn't be preset.
        self.output_contains_not(buf, ['LP_MODULE', 'module_notify',
                                       'linux/module.h', 'klp_funcs'
                                       ])


        # As the config ionly targets x86_64, IS_ENABLED should be set
        self.output_contains(buf, ['#if IS_ENABLED'])

if __name__ == '__main__':
    unittest.main()
