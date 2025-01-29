# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import importlib
import logging

PLUGINS_PATH = "klpbuild.plugins."

def try_run_plugin(name, args):
    """
    Attempts to run a plugin by importing the corresponding module and
    executing its `run` function.

    Args:
        name (str): The name of the plugin module to import.
        args (Any): The arguments to pass to the `run` function of the plugin.

    Raises:
        AssertionError: If the module does not have a `run` function.
        ModuleNotFoundError: If the specified plugin cannot be found.
    """
    logging.debug("Trying to run plugin %s", name)

    module = importlib.import_module(PLUGINS_PATH + name)
    assert hasattr(module, "run"), f"Module {name} is not a plugin!"

    module.run(args)
