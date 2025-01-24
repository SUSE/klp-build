# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

from functools import wraps
from pathlib import Path, PurePath
from configparser import ConfigParser
import logging
import os


_loaded = False
_config = ConfigParser()


def __check_config_is_loaded(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _loaded
        if not _loaded : 
            __load_user_conf()
            _loaded = True
        return func(*args, **kwargs)
    return wrapper


def __setup_user_env(basedir):
    workdir = Path(basedir)/"livepatches"
    datadir = Path(basedir)/"data"
    user_conf_file = __get_user_conf_file()

    config = ConfigParser(allow_no_value=True)

    config['Paths'] = {'work_dir': workdir,
                       'data_dir': datadir,
                       '## SUSE internal use only ##': None,
                       '#kgr_patches_dir': 'kgraft-patches/',
                       '#kgr_patches_tests_dir': 'kgraft-patches_testscripts/',
                       '#kernel_src_dir': 'kernel-src/'}

    config['Settings'] = {'workers': 4}

    logging.info("Creating default user configuration: '%s'", user_conf_file)
    os.makedirs(os.path.dirname(user_conf_file), exist_ok=True)
    with open(user_conf_file, 'w') as f:
        config.write(f)

    os.makedirs(workdir, exist_ok=True)
    os.makedirs(datadir, exist_ok=True)

def __load_user_conf():
    user_conf_file = __get_user_conf_file()
    if not user_conf_file.is_file():
        logging.warning("Warning: user configuration file not found")
        __setup_user_env(Path.home()/"klp")

    logging.info("Loading user configuration from '%s'", user_conf_file)
    _config.read(user_conf_file)

    # Check mandatory fields
    for s in ['Paths', 'Settings']:
        if s not in _config:
            raise ValueError(f"config: '{s}' section not found")


@__check_config_is_loaded
def get_user_settings(entry, isopt=False):
    if entry not in _config['Settings']:
        if isopt:
            return ""
        raise ValueError(f"config: '{entry}' entry not found")

    return _config['Settings'][entry]


@__check_config_is_loaded
def get_tests_path(lp_name):
    kgr_path = get_user_path('kgr_patches_tests_dir')

    test_sh = Path(kgr_path)/(lp_name+"_test_script.sh")
    if test_sh.is_file():
        return test_sh

    test_dir_sh = kgr_path/lp_name/"test_script.sh"
    if test_dir_sh.is_file():
        # For more complex tests we support using a directory containing
        # as much files as needed. A `test_script.sh` is still required
        # as an entry point.
        return PurePath(test_dir_sh).parent

    raise RuntimeError(f"Couldn't find {test_sh} or {test_dir_sh}")

@__check_config_is_loaded
def get_user_path(entry, isdir=True, isopt=False):
    if entry not in _config['Paths']:
        if isopt:
            return Path("")
        raise ValueError(f"config: '{entry}' entry not found")

    p = Path(_config['Paths'][entry])
    if not p.exists():
        raise ValueError(f"'{p}' file or directory not found")
    if isdir and not p.is_dir():
        raise ValueError("{p} should be a directory")
    if not isdir and not p.is_file():
        raise ValueError("{p} should be a file")

    return p

def __get_user_conf_file():
    return Path.home()/".config/klp-build/config"
