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

if __name__ == '__main__':
    unittest.main()
