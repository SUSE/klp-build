import unittest

import sys
sys.path.append('..')
import klp_args

#--bsc 55555 --cve 2023-28466 --module tls --conf CONFIG_TLS --file-funcs net/tls/tls_main.c do_tls_getsockopt_conf --archs x86_64
class KlpBuildMainTest(unittest.TestCase):
    def test_incorrect_arch(self):
        args = ['setup', '--bsc', '55555', '--cve', '2023-28466', '--module',
                'tls']

        arch_args = args + ['--archs', 'x86']
        self.assertRaises(ValueError, klp_args.main_func, arch_args)

if __name__ == '__main__':
    unittest.main()
