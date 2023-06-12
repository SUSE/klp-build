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

        #self.setup_and_assert(v, RuntimeError, 'File drivers/net/tuna.c not found')

        with self.assertRaises(RuntimeError) as ar:
            self.setup(v, True)
            ccp = CCP(v['bsc'], cs, [])
            ccp.run_ccp()

        self.assertEqual(str(ar.exception),
            '15.3u32:lib/seq_buf.o is not compiled with livepatch support (-pg flag)')

if __name__ == '__main__':
    unittest.main()
