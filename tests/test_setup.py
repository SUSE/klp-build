# SPDX-License-Identifier: GPL-2.0-only # # Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect
import logging
import pytest

from klpbuild.plugins.setup import setup, setup_manual
from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib import utils
from tests.utils import get_codestreams_file

CS = "15.5u23"
DEFAULT_DATA = {"cve": None, "lp_filter": CS, "conf": "CONFIG_TUN", "no_check": True}


def test_missing_file_funcs():
    with pytest.raises(ValueError, match=r"You need to specify at least one of the file-funcs variants!"):
        setup_manual({}, utils.ARCHS, None, None, [], [], [])


def test_missing_conf_prefix(caplog):
    with pytest.raises(SystemExit):
        file_funcs = [["drivers/net/tuna.c", "tun_chr_ioctl", "tun_free_netdev"]]
        setup_manual([Codestream(CS)], utils.ARCHS, "TUN", None, file_funcs, [], [])
    assert "Invalid config 'TUN': Missing CONFIG_ prefix" in caplog.text


def test_file_funcs_ok():
    # Check for multiple variants of file-funcs
    cs = Codestream(CS)

    setup_manual([cs], utils.ARCHS, "CONFIG_TUN", "tun",
                 [["drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]], [], [])
    assert cs.files["drivers/net/tun.c"] == \
            {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}

    setup_manual([cs], utils.ARCHS, "CONFIG_TUN", "tun", [],
                 [["tun", "drivers/net/tun1.c", "tun_chr_ioctl", "tun_free_netdev"]], [])
    assert cs.files["drivers/net/tun1.c"] == \
            {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}

    setup_manual([cs], utils.ARCHS, "CONFIG_TUN", "tun", [], [],
                 [["CONFIG_TUN", "tun", "drivers/net/tun2.c", "tun_chr_ioctl", "tun_free_netdev"]])
    assert cs.files["drivers/net/tun2.c"] == \
            {"module": "tun", "conf": "CONFIG_TUN", "symbols": ["tun_chr_ioctl", "tun_free_netdev"]}


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
    micro_cs = "6.0u11"
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
    cs = Codestream(CS)
    setup_manual([cs], utils.ARCHS, "CONFIG_NET_SCH_QFQ", "sch_qfq",
                 [["net/sched/sch_qfq.c", "qfq_change_class"]],
                 [["btsdio", "drivers/bluetooth/btsdio.c",
                   "btsdio_probe", "btsdio_remove"]], [])

    sch = cs.files["net/sched/sch_qfq.c"]
    bts = cs.files["drivers/bluetooth/btsdio.c"]
    assert sch["conf"] == bts["conf"]
    assert sch["module"] == "sch_qfq"
    assert bts["module"] == "btsdio"

    setup_manual([cs], utils.ARCHS, "CONFIG_NET_SCH_QFQ", "sch_qfq",
                 [["net/sched/sch_qfq.c", "qfq_change_class"]], [],
                 [["CONFIG_BT_HCIBTSDIO", "btsdio",
                   "drivers/bluetooth/btsdio.c", "btsdio_probe", "btsdio_remove"]])

    sch = cs.files["net/sched/sch_qfq.c"]
    bts = cs.files["drivers/bluetooth/btsdio.c"]
    assert sch["conf"] == "CONFIG_NET_SCH_QFQ"
    assert sch["module"] == "sch_qfq"
    assert bts["conf"] == "CONFIG_BT_HCIBTSDIO"
    assert bts["module"] == "btsdio"


def test_symbol_with_noinstr(caplog):
    # Make sure we error out in the case of a configuration entry that is not enabled
    # on a codestream
    # Make sure that we detect when a symbol cannot be patched on setup phase
    lp = "bsc_" + inspect.currentframe().f_code.co_name

    lp_default_data = {"cve": None, "lp_filter": CS, "conf": "CONFIG_SUSE_KERNEL", "no_check": True}
    for arch in ["x86_64", "ppc64le", "s390x"]:
        with pytest.raises(SystemExit):
            setup_args = {
                "lp_name": lp,
                "archs": [arch],
                "module": "vmlinux",
                "file_funcs": [["kernel/time/timekeeping.c", "__ktime_get_real_seconds"]],
                "mod_file_funcs": [],
                "conf_mod_file_funcs": [],
                **lp_default_data
            }
            setup(**setup_args)

    assert "Symbol __ktime_get_real_seconds has tracing disabled." in caplog.text
