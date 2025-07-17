# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import dataclasses
import json

from collections import OrderedDict
from natsort import natsorted

from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib.config import get_user_path

# Dataclass for storing codestream data
@dataclasses.dataclass
class CodestreamData:
    cve: str
    archs: list[str]
    patched_kernels: list[str]
    patched_cs: list[str]
    upstream: list[str]


_cs_data = CodestreamData("", [], [], [], {})
_codestreams = {}


def load_codestreams(lp_name):
    """
    Load the codestreams data from file.

    Args:
        lp_name (str): The name of the live patch.
    """
    global _cs_data

    cs_file = __get_cs_file(lp_name)

    if cs_file.is_file():
        with open(cs_file) as f:
            jfile = json.loads(f.read(), object_pairs_hook=OrderedDict)
            _cs_data = CodestreamData(cve=jfile["cve"],
                                          archs=jfile["archs"],
                                          patched_kernels=jfile["patched_kernels"],
                                          patched_cs=jfile["patched_cs"],
                                          upstream=jfile["upstream"])

            json_cs = jfile["codestreams"]
            for cs in natsorted(json_cs.keys()):
                _codestreams[cs] = Codestream.from_data(json_cs[cs])


def store_codestreams(lp_name, working_cs):
    """
    Update and save the codestream data to a JSON file.

    Args:
        lp_name (str): The name of the live patch.
        working_cs (dict): codestreams to be updated.
    """
    # Update the latest state of the codestreams
    for cs in working_cs:
        _codestreams[cs.name()] = cs

    # Format each codestream for the json
    cs_data = {}
    for key, cs in _codestreams.items():
        cs_data[key] = cs.data()

    data = {"archs": _cs_data.archs,
            "upstream": _cs_data.upstream,
            "cve": _cs_data.cve,
            "patched_cs": _cs_data.patched_cs,
            "patched_kernels": _cs_data.patched_kernels,
            "codestreams": cs_data}

    cs_file = __get_cs_file(lp_name)
    with open(cs_file, "w") as f:
        f.write(json.dumps(data, indent=4))


def __get_cs_file(lp_name):
    """
    Get the path to the codestreams JSON file for the specified live patch.

    Args:
        lp_name (str): The name of the live patch.

    Returns:
        Path: The path to the codestreams JSON file.
    """
    workdir = get_user_path('work_dir')
    return workdir/lp_name/'codestreams.json'


def get_codestream_by_name(name):
    """
    Retrieve a codestream by its name.

    Args:
        name (str): The name of the codestream.

    Returns:
        Codestream: The requested codestream, or None if not found.
    """
    return _codestreams.get(name, None)


def get_codestreams_dict():
    """
    Retrieve the dictionary of all codestreams.

    Returns:
        dict: A dictionary of all codestreams.
    """
    return _codestreams


def get_codestreams_items():
    """
    Retrieve the items (key-value pairs) of the codestreams dictionary.

    Returns:
        dict_items: The items of the codestreams dictionary.
    """
    return _codestreams.items()


def get_codestreams_data(name: str):
    """
    Retrieve the codestream data for a given attribute name.

    Args:
        name (str): The name of the codestream attribute to retrieve.

    Returns:
        The value of the specified codestream attribute.
    """
    assert hasattr(_cs_data, name)
    return getattr(_cs_data, name)


def set_codestreams_data(**kwargs):
    """
    Set the codestream data for the global _cs_data instance.

    Args:
        **kwargs: Key-value pairs of attributes and values to update in _cs_data.
    """
    for key, value in kwargs.items():
        assert hasattr(_cs_data, key)
        setattr(_cs_data, key, value)
