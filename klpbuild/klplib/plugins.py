# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import argparse
import importlib
import inspect
import logging
import pkgutil


PLUGINS_PACKAGE_NAME = "klpbuild.plugins"
PLUGINS_PATH = PLUGINS_PACKAGE_NAME + "."

def try_run_plugin(name, args):
    """
    Attempts to run a plugin by importing the corresponding module and
    executing its `run` function.

    Args:
        name (str): The name of the plugin module to import.
        args (Any): The main argument parser.

    Raises:
        AssertionError: If the module does not have a `run` function.
        ModuleNotFoundError: If the specified plugin cannot be found.
    """
    logging.debug("Trying to run plugin %s", name)

    real_name = name.replace("-", "_")
    module = __get_plugin(real_name)
    assert hasattr(module, "run"), f"Module {name} is not a plugin!"

    run_func = getattr(module, "run")
    required_args = __get_required_plugin_args(run_func, args)
    run_func(**required_args)


def register_plugins_argparser(subparser):
    """
    Register the parser of each plugin to the subparser.

    :param subparser: the subparser whose plugin parser will be added
    """
    for module in __iter_plugins():
        # TODO: use 'assert' instead of 'if' when all the plugins are ready
        if hasattr(module, "register_argparser"):
            module.register_argparser(subparser)


def __get_required_plugin_args(func, args):
    """
    Extracts arguments from an `argparse.Namespace` object and returns only
    those that are needed as keyword arguments by the function.

    Args:
        func (function): The name of the plugin module to import.
        args (ArgumentParser): The main argument parser.

    Raises:
        AssertionError: If the provided argument is not an instance of
        `argparse.Namespace`.

    """
    assert isinstance(args, argparse.Namespace)

    all_args = vars(args)
    required_args_names = inspect.getfullargspec(func).args
    return  {arg_name: all_args.get(arg_name, None) for arg_name in required_args_names}


def __iter_plugins():
    """
    Iterates plugins.

    """
    module = importlib.import_module(PLUGINS_PACKAGE_NAME)
    for _, module_name, _ in pkgutil.iter_modules(module.__path__):
        yield __get_plugin(module_name)


def __get_plugin(name):
    """
    Retrieve the plugin given its name.

    :param name: the name of the plugin to be retrieved
    """
    return importlib.import_module(PLUGINS_PATH + name)
