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
    """
    This decorator checks whether the configuration has been loaded. If not,
    it loads the configuration and then calls the wrapped function.

    Args:
        func (function): The function to be wrapped.

    Returns:
        function: The wrapped function.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _loaded
        if not _loaded:
            __load_user_conf()
            _loaded = True
        return func(*args, **kwargs)
    return wrapper


@__check_config_is_loaded
def get_user_settings(entry, isopt=False):
    """
    Retrieves the user setting for a given entry from the configuration.

    Args:
        entry (str): The setting entry to retrieve.
        isopt (bool): If True, returns an empty string if the entry is not found.

    Raises:
        ValueError: If the entry is not found in the 'Settings' section.

    Returns:
        str: The value of the specified setting entry.
    """
    if entry not in _config['Settings']:
        if isopt:
            return ""
        raise ValueError(f"config: '{entry}' entry not found")

    return _config['Settings'][entry]


@__check_config_is_loaded
def get_tests_path(lp_name):
    """
    Retrieves the path of the test script associated with a given live patch name.

    Args:
        lp_name (str): The live patch name to search for the test script.

    Raises:
        RuntimeError: If no test script is found.

    Returns:
        Path: The path to the test script or directory containing it.
    """
    kgr_path = get_user_path('kgr_patches_tests_dir')

    test_sh = Path(kgr_path, f"{lp_name}_test_script.sh")
    if test_sh.is_file():
        return test_sh

    test_dir_sh = Path(kgr_path, f"{lp_name}/test_script.sh")
    if test_dir_sh.is_file():
        # For more complex tests we support using a directory containing
        # as much files as needed. A `test_script.sh` is still required
        # as an entry point.
        return PurePath(test_dir_sh).parent

    raise RuntimeError(f"Couldn't find {test_sh} or {test_dir_sh}")


@__check_config_is_loaded
def get_user_path(entry, isdir=True, isopt=False):
    """
    Retrieves the path for a given entry from the configuration and checks its validity.

    Args:
        entry (str): The path entry to retrieve.
        isdir (bool): If True, checks if the path is a directory; otherwise checks if it's a file.
        isopt (bool): If True, returns an empty string if the entry is not found.

    Raises:
        ValueError: If the entry is not found, or the path is not of the expected type (file or directory).

    Returns:
        Path: The resolved and validated path.
    """
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
    """
    Returns the file path to the user configuration file.

    The configuration file is located in the user's home directory under
    ".config/klp-build/config".

    Returns:
        Path: The path to the user configuration file.
    """
    return Path.home()/".config/klp-build/config"


def __setup_user_env(basedir):
    """
    Sets up the user's environment by creating the necessary directories
    and writing the default configuration file.

    Args:
        basedir (Path): The base directory to create the environment in.
    """
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
    """
    Loads the user configuration file and reads its contents into the global
    `_config` variable.

    If the configuration file is not found, it calls `__setup_user_env()` to
    create a default configuration file.

    Raises:
        ValueError: If required sections 'Paths' or 'Settings' are missing in the config.
    """
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
