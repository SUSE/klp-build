# SPDX-License-Identifier: GPL-2.0-only # # Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect
import logging
import pytest

from klpbuild.setup import Setup
from klpbuild import utils

CS = "15.5u19"
DEFAULT_DATA = {"cve": None, "lp_filter": CS, "lp_skips": None, "conf": "CONFIG_TUN", "no_check": False}


def test_missing_file_funcs():
    with pytest.raises(ValueError, match=r"You need to specify at least one of the file-funcs variants!"):
        Setup.setup_file_funcs(None, None, [], [], [])


def test_missing_conf_prefix():
    with pytest.raises(ValueError, match=r"Please specify --conf with CONFIG_ prefix"):
        Setup.setup_file_funcs("TUN", None, [], [], [])


def test_file_funcs_ok():
    # Check for multiple variants of file-funcs
    assert Setup.setup_file_funcs("CONFIG_TUN", "tun", [
                                  ["drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]], [], []) == \
        {"drivers/net/tun.c": {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}}

    assert Setup.setup_file_funcs("CONFIG_TUN", None, [],
                                  [["tun", "drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]], []) == \
        {"drivers/net/tun.c": {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}}

    assert Setup.setup_file_funcs(None, None, [], [],
                                  [["CONFIG_TUN", "tun", "drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]]) == \
        {"drivers/net/tun.c": {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}}


def test_non_existent_file():
    with pytest.raises(RuntimeError, match=r".*: File drivers/net/tuna.c not found on .*"):
        lp = "bsc_" + inspect.currentframe().f_code.co_name
        lp_setup = Setup(lp)

        ffuncs = {"drivers/net/tuna.c": {"module": "tun", "conf": "CONFIG_TUN",
                                         "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}}

        codestreams = lp_setup.setup_codestreams(DEFAULT_DATA)
        lp_setup.setup_project_files(codestreams, ffuncs, utils.ARCHS)


def test_non_existent_module():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with pytest.raises(RuntimeError, match=r"Module not found: tuna"):
        lp = "bsc_" + inspect.currentframe().f_code.co_name
        lp_setup = Setup(lp)

        ffuncs = {"drivers/net/tun.c": {"module": "tuna", "conf": "CONFIG_TUN",
                                        "symbols": ["tun_chr_ioctll", "tun_free_netdev"]}}

        codestreams = lp_setup.setup_codestreams(DEFAULT_DATA)
        lp_setup.setup_project_files(codestreams, ffuncs, utils.ARCHS)


def test_invalid_sym(caplog):
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with caplog.at_level(logging.WARNING):
        lp = "bsc_" + inspect.currentframe().f_code.co_name
        lp_setup = Setup(lp)

        ffuncs = {"drivers/net/tun.c": {"module": "tun", "conf": "CONFIG_TUN",
                                        "symbols": ["tun_chr_ioctll", "tun_free_netdev"]}}

        codestreams = lp_setup.setup_codestreams(DEFAULT_DATA)
        lp_setup.setup_project_files(codestreams, ffuncs, utils.ARCHS)

    assert "Symbols tun_chr_ioctll not found on tun" in caplog.text


def test_valite_conf_mod_file_funcs():
    # Check that passing mod-file-funcs can create entries differently from general
    # --module and --file-funcs
    ffuncs = Setup.setup_file_funcs("CONFIG_NET_SCH_QFQ", "sch_qfq", [["net/sched/sch_qfq.c", "qfq_change_class"]], [
                                    ["btsdio", "drivers/bluetooth/btsdio.c", "btsdio_probe", "btsdio_remove"]], [])

    sch = ffuncs["net/sched/sch_qfq.c"]
    bts = ffuncs["drivers/bluetooth/btsdio.c"]
    assert sch["conf"] == bts["conf"]
    assert sch["module"] == "sch_qfq"
    assert bts["module"] == "btsdio"

    ffuncs = Setup.setup_file_funcs("CONFIG_NET_SCH_QFQ", "sch_qfq",
                                    [["net/sched/sch_qfq.c", "qfq_change_class"]], [],
                                    [["CONFIG_BT_HCIBTSDIO", "btsdio",
                                        "drivers/bluetooth/btsdio.c", "btsdio_probe", "btsdio_remove"]])

    sch = ffuncs["net/sched/sch_qfq.c"]
    bts = ffuncs["drivers/bluetooth/btsdio.c"]
    assert sch["conf"] == "CONFIG_NET_SCH_QFQ"
    assert sch["module"] == "sch_qfq"
    assert bts["conf"] == "CONFIG_BT_HCIBTSDIO"
    assert bts["module"] == "btsdio"
