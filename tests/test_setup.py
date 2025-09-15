# SPDX-License-Identifier: GPL-2.0-only # # Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect
import logging
import pytest

from klpbuild.plugins.setup import setup, setup_file_funcs
from tests.utils import get_codestreams_file
from klpbuild.klplib import utils

CS = "15.5u19"
DEFAULT_DATA = {"cve": None, "lp_filter": CS, "conf": "CONFIG_TUN", "no_check": True}


def test_missing_file_funcs():
    with pytest.raises(ValueError, match=r"You need to specify at least one of the file-funcs variants!"):
        setup_file_funcs(None, None, [], [], [])


def test_missing_conf_prefix():
    with pytest.raises(ValueError, match=r"Please specify --conf with CONFIG_ prefix"):
        setup_file_funcs("TUN", None, [], [], [])


def test_file_funcs_ok():
    # Check for multiple variants of file-funcs
    assert setup_file_funcs("CONFIG_TUN", "tun", [
                                  ["drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]], [], []) == \
        {"drivers/net/tun.c": {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}}

    assert setup_file_funcs("CONFIG_TUN", None, [],
                                  [["tun", "drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]], []) == \
        {"drivers/net/tun.c": {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}}

    assert setup_file_funcs(None, None, [], [],
                                  [["CONFIG_TUN", "tun", "drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]]) == \
        {"drivers/net/tun.c": {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}}


def test_non_existent_file():
    with pytest.raises(RuntimeError, match=r".*: File drivers/net/tuna.c not found"):
        lp = "bsc_" + inspect.currentframe().f_code.co_name

        setup_args = {
            "lp_name" : lp,
            "archs" : utils.ARCHS,
            "module" : "tun",
            "file_funcs" : [["drivers/net/tuna.c", "tun_chr_ioctl", "tun_free_netdev"]],
            "mod_file_funcs" : [],
            "conf_mod_file_funcs" : [],
            **DEFAULT_DATA
        }
        setup(**setup_args)


def test_non_existent_module():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with pytest.raises(RuntimeError, match=r"Module not found: tuna"):
        lp = "bsc_" + inspect.currentframe().f_code.co_name

        setup_args = {
            "lp_name" : lp,
            "archs" : utils.ARCHS,
            "module" : "tuna",
            "file_funcs" : [["drivers/net/tun.c", "tun_chr_ioctll", "tun_free_netdev"]],
            "mod_file_funcs" : [],
            "conf_mod_file_funcs" : [],
            **DEFAULT_DATA
        }
        setup(**setup_args)


def test_invalid_sym(caplog):
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with caplog.at_level(logging.WARNING):
        lp = "bsc_" + inspect.currentframe().f_code.co_name

        setup_args = {
            "lp_name" : lp,
            "archs" : utils.ARCHS,
            "module" : "tun",
            "file_funcs" : [["drivers/net/tun.c", "tun_chr_ioctll", "tun_free_netdev"]],
            "mod_file_funcs" : [],
            "conf_mod_file_funcs" : [],
            **DEFAULT_DATA
        }
        setup(**setup_args)

    assert "Symbols tun_chr_ioctll not found on tun" in caplog.text


def test_valid_micro_patchid():
    # Make sure that patchid is informed for SLE MICRO
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    micro_cs = "6.0u2"
    micro_data = {"cve": None, "lp_filter": micro_cs, "conf": "CONFIG_TUN", "no_check": True}

    setup_args = {
        "lp_name" : lp,
        "archs" : utils.ARCHS,
        "module" : "tun",
        "file_funcs" : [["drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]],
        "mod_file_funcs" : [],
        "conf_mod_file_funcs" : [],
        **micro_data
    }
    setup(**setup_args)

    cs_conf = get_codestreams_file(lp)["codestreams"][micro_cs]

    assert cs_conf["patchid"]


def test_valite_conf_mod_file_funcs():
    # Check that passing mod-file-funcs can create entries differently from general
    # --module and --file-funcs
    ffuncs = setup_file_funcs("CONFIG_NET_SCH_QFQ", "sch_qfq", [["net/sched/sch_qfq.c", "qfq_change_class"]], [
                                    ["btsdio", "drivers/bluetooth/btsdio.c", "btsdio_probe", "btsdio_remove"]], [])

    sch = ffuncs["net/sched/sch_qfq.c"]
    bts = ffuncs["drivers/bluetooth/btsdio.c"]
    assert sch["conf"] == bts["conf"]
    assert sch["module"] == "sch_qfq"
    assert bts["module"] == "btsdio"

    ffuncs = setup_file_funcs("CONFIG_NET_SCH_QFQ", "sch_qfq",
                                    [["net/sched/sch_qfq.c", "qfq_change_class"]], [],
                                    [["CONFIG_BT_HCIBTSDIO", "btsdio",
                                        "drivers/bluetooth/btsdio.c", "btsdio_probe", "btsdio_remove"]])

    sch = ffuncs["net/sched/sch_qfq.c"]
    bts = ffuncs["drivers/bluetooth/btsdio.c"]
    assert sch["conf"] == "CONFIG_NET_SCH_QFQ"
    assert sch["module"] == "sch_qfq"
    assert bts["conf"] == "CONFIG_BT_HCIBTSDIO"
    assert bts["module"] == "btsdio"


def test_valite_conf_unsupported_arch():
    # Make sure we error out in the case of a configuration entry that is not enabled
    # on a codestream
    lp = "bsc_" + inspect.currentframe().f_code.co_name

    # CONFIG_HID is not enabled on s390x, so setup should fail here
    LP_DEFAULT_DATA = {"cve": None, "lp_filter": CS, "conf": "CONFIG_HID", "no_check": True}
    with pytest.raises(RuntimeError, match=rf"{CS}: CONFIG_HID not set on s390x"):
        setup_args = {
            "lp_name": lp,
            "archs": utils.ARCHS,
            "module": "vmlinux",
            "file_funcs": [["drivers/hid/hid-core.c", "hid_alloc_report_buf"]],
            "mod_file_funcs": [],
            "conf_mod_file_funcs": [],
            **LP_DEFAULT_DATA
        }
        setup(**setup_args)

    # It shoudl succeed when s390x is removed from the setup command
    setup_args = {
        "lp_name": lp,
        "archs": ["x86_64", "ppc64le"],
        "module": "vmlinux",
        "file_funcs": [["drivers/hid/hid-core.c", "hid_alloc_report_buf"]],
        "mod_file_funcs": [],
        "conf_mod_file_funcs": [],
        **LP_DEFAULT_DATA
    }
    setup(**setup_args)
