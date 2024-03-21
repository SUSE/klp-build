import logging
import os
import unittest

from klpbuild.ccp import CCP
from tests import utils


class TemplTesting(utils.TestUtils):
    def setUp(self):
        os.environ["KLP_KERNEL_SOURCE"] = ""

        logging.disable(logging.INFO)
        logging.disable(logging.WARNING)

    def test_templ_with_externalized_vars(self):
        v = self.sargs()
        cs = "15.3u32"
        v["filter"] = cs
        v["file_funcs"] = [["lib/seq_buf.c", "seq_buf_putmem_hex"]]

        self.setup(v, True)
        ccp = CCP(v["bsc"], cs, [])
        ccp.run_ccp()

        # As we passed vmlinux as module, we don't have the module notifier and
        # LP_MODULE, linux/module.h is not included
        # As the code is using the default archs, which is all of them, the
        # IS_ENABLED macro shouldn't exist
        self.output_contains_not(v, cs, ["LP_MODULE", "module_notify", "linux/module.h", "#if IS_ENABLED"])

        # For this file and symbol, there is one symbol to be looked up, so
        # klp_funcs should be present
        self.output_contains(v, cs, ["klp_funcs"])

    def test_templ_without_externalized_vars(self):
        v = self.sargs()
        cs = "15.5u0"
        v["filter"] = cs
        v["file_funcs"] = [["net/ipv6/rpl.c", "ipv6_rpl_srh_size"]]
        v["conf"] = "CONFIG_IPV6"
        v["archs"] = ["x86_64"]

        self.setup(v, True)
        ccp = CCP(v["bsc"], cs, [])
        ccp.run_ccp()

        # As we passed vmlinux as module, we don't have the module notifier and
        # LP_MODULE, linux/module.h is not included
        # For this file and symbol, no externalized symbols are used, so
        # klp_funcs shouldn't be preset.
        self.output_contains_not(v, cs, ["LP_MODULE", "module_notify", "linux/module.h", "klp_funcs"])

        # As the config only targets x86_64, IS_ENABLED should be set
        self.output_contains(v, cs, ["#if IS_ENABLED"])

    def test_check_header_file_included(self):
        v = self.sargs()
        cs = "15.5u0"
        v["filter"] = cs
        v["file_funcs"] = [["fs/exec.c", "begin_new_exec"], ["kernel/events/core.c", "perf_event_exec"]]
        v["conf"] = "CONFIG_IPV6"
        v["archs"] = ["x86_64"]

        self.setup(v, True)
        ccp = CCP(v["bsc"], cs, [])
        ccp.run_ccp()

        # Check if the livepatch general file contains the header
        self.output_contains(v, cs, ["Upstream commit:"])
        self.output_contains_not(v, cs, ["Upstream commit:"], f'bsc{v["bsc"]}_kernel_events_core.c')
        self.output_contains_not(v, cs, ["Upstream commit:"], f'bsc{v["bsc"]}_fs_exec.c')


if __name__ == "__main__":
    unittest.main()
