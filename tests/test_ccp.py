# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import logging
import os
import unittest

from klpbuild.ccp import CCP
from tests import utils


class CcpTesting(utils.TestUtils):
    def setUp(self):
        logging.disable(logging.INFO)

    def test_detect_file_without_ftrace_support(self):
        v = self.sargs()
        cs = "15.3u32"
        v["filter"] = cs
        v["module"] = "vmlinux"
        v["file_funcs"] = [["lib/seq_buf.c", "seq_buf_putmem_hex"]]

        with self.assertLogs(level="WARNING") as logs:
            self.setup(v, True)
            ccp = CCP(v["bsc"], cs, [])
            ccp.run_ccp()

        self.assertRegex(logs.output[0], r"lib/seq_buf.o is not compiled with livepatch support \(\-pg flag\)")

    def test_group_classify(self):
        group = CCP.classify_codestreams(["15.2u10", "15.2u11", "15.3u10", "15.3u12"])
        self.assertEqual(group, "15.2u10-11 15.3u10-12")


if __name__ == "__main__":
    unittest.main()
