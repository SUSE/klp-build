# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

import inspect
import json
import logging
from pathlib import Path
import pytest

from klpbuild.setup import Setup
import klpbuild.utils as utils
from tests.utils import get_workdir

cs = "15.5u19"

def test_missing_file_funcs():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with pytest.raises(ValueError, match=r"You need to specify at least one of the file-funcs variants!"):
        Setup(lp_name=lp, lp_filter=cs, cve=None, mod_file_funcs=[],
              conf_mod_file_funcs=[], file_funcs=[], mod_arg="vmlinux", conf=None,
              archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()


def test_missing_conf_prefix():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with pytest.raises(ValueError, match=r"Please specify --conf with CONFIG_ prefix"):
        Setup(lp_name=lp, lp_filter=cs, cve=None, mod_file_funcs=[],
              conf_mod_file_funcs=[], file_funcs=[], conf="TUN", mod_arg="vmlinux",
              archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()


# Check for multiple variants of file-funcs
def test_file_funcs_ok():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    Setup(lp_name=lp, lp_filter=cs, cve=None, conf="CONFIG_TUN",
          mod_arg="tun", mod_file_funcs=[], conf_mod_file_funcs=[],
          file_funcs = [["drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]],
          archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()

    Setup(lp_name=lp, lp_filter=cs, cve=None, conf="CONFIG_TUN",
          file_funcs=[], conf_mod_file_funcs=[], mod_arg=None,
          mod_file_funcs = [["tun", "drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]],
          archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()

    Setup(lp_name=lp, lp_filter=cs, cve=None, conf="CONFIG_TUN", mod_file_funcs=[],
          file_funcs=[], mod_arg=None,
          conf_mod_file_funcs = [["CONFIG_TUN", "tun", "drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]],
          archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()


def test_non_existent_file():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with pytest.raises(RuntimeError, match=r".*: File drivers/net/tuna.c not found on .*"):
        Setup(lp_name=lp, lp_filter=cs, cve=None, conf="CONFIG_TUN", mod_arg="tun",
              mod_file_funcs=[], conf_mod_file_funcs=[],
              file_funcs = [["drivers/net/tuna.c", "tun_chr_ioctl", "tun_free_netdev"]],
              archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()


def test_non_existent_module():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with pytest.raises(RuntimeError, match=r"Module not found: tuna"):
        Setup(lp_name=lp, lp_filter=cs, cve=None, conf="CONFIG_TUN", mod_arg="tuna",
              mod_file_funcs=[], conf_mod_file_funcs=[],
              file_funcs = [["drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]],
              archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()


def test_invalid_sym(caplog):
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    with caplog.at_level(logging.WARNING):
        Setup(lp_name=lp, lp_filter=cs, cve=None, conf="CONFIG_TUN", mod_arg="tun",
              mod_file_funcs=[], conf_mod_file_funcs=[],
              file_funcs = [["drivers/net/tun.c", "tun_chr_ioctll", "tun_free_netdev"]],
              archs=utils.ARCHS, skips=None, no_check=False).setup_project_files()

    assert "Symbols tun_chr_ioctll not found on tun" in caplog.text


def test_check_conf_mod_file_funcs():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    Setup(lp_name=lp, lp_filter=cs, cve=None, mod_arg="sch_qfq", conf="CONFIG_TUN",
          mod_file_funcs=[], file_funcs=[],
          conf_mod_file_funcs = [["CONFIG_TUN", "tun", "drivers/net/tun.c", "tun_chr_ioctl", "tun_free_netdev"]],
          archs=[utils.ARCH], skips=None, no_check=False).setup_project_files()


def test_check_conf_mod_file_funcs():
    lp = "bsc_" + inspect.currentframe().f_code.co_name
    # Check that passing mod-file-funcs can create entries differently from general
    # --module and --file-funcs
    Setup(lp_name=lp, lp_filter=cs, cve=None, mod_arg="sch_qfq", conf="CONFIG_NET_SCH_QFQ",
          conf_mod_file_funcs=[], file_funcs=[["net/sched/sch_qfq.c", "qfq_change_class"]],
          mod_file_funcs=[["btsdio", "drivers/bluetooth/btsdio.c", "btsdio_probe", "btsdio_remove"]],
          archs=[utils.ARCH], skips=None, no_check=False).setup_project_files()

    with open(Path(get_workdir(lp, cs), "codestreams.json")) as f:
        data = json.loads(f.read())["codestreams"][cs]["files"]

    sch = data["net/sched/sch_qfq.c"]
    bts = data["drivers/bluetooth/btsdio.c"]
    assert sch["conf"] == bts["conf"]
    assert sch["module"] == "sch_qfq"
    assert bts["module"] == "btsdio"

    # Rerun setup and now conf and module should be different
    Setup(lp_name=lp, lp_filter=cs, cve=None, mod_arg="sch_qfq", conf="CONFIG_NET_SCH_QFQ",
          mod_file_funcs=[], file_funcs=[["net/sched/sch_qfq.c", "qfq_change_class"]],
          conf_mod_file_funcs = [ ["CONFIG_BT_HCIBTSDIO", "btsdio",
                                   "drivers/bluetooth/btsdio.c", "btsdio_probe",
                                   "btsdio_remove"] ],
          archs=[utils.ARCH], skips=None, no_check=False).setup_project_files()

    with open(Path(get_workdir(lp, cs), "codestreams.json")) as f:
        data = json.loads(f.read())["codestreams"][cs]["files"]

    sch = data["net/sched/sch_qfq.c"]
    bts = data["drivers/bluetooth/btsdio.c"]
    assert sch["conf"] == "CONFIG_NET_SCH_QFQ"
    assert sch["module"] == "sch_qfq"
    assert bts["conf"] == "CONFIG_BT_HCIBTSDIO"
    assert bts["module"] == "btsdio"
