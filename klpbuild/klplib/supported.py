# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import re
import requests
from pathlib import Path

from klpbuild.klplib import utils
from klpbuild.klplib.codestream import Codestream

SUPPORTED_CS_URL = "https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv"
SUSE_CERT = Path("/etc/ssl/certs/SUSE_Trust_Root.pem")

def get_supported_codestreams():
    """
    Download and parse the list of supported codestreams.

    Returns:
        list[Codestream]: A list of supported codestreams.
    """
    supported_codestreams = []
    lines = __download_supported_file() if not utils.in_test_mode() else __load_supported_file();

    for line in lines:
        # remove the last two columns, which are dates of the line
        # and add a fifth field with the forth one + rpm- prefix, and
        # remove the build counter number
        full_cs, proj, kernel_full, _, _ = line.split(",")

        kernel = re.sub(r"\.\d+$", "", kernel_full)

        # MICRO releases contain project/patchid format
        if "/" in proj:
            proj, patchid = proj.split("/")
        else:
            patchid = ""

        supported_codestreams.append(Codestream.from_codestream(full_cs, proj,
                                                                patchid,
                                                                kernel))
    return supported_codestreams

def __load_supported_file():
    """
    Read and return the lines of the supported file.

    Returns:
        list[str]: The list of lines of the supported file, excluding the
        header.
    """
    with open("tests/supported.csv") as file:
        return file.readlines()[1:]

def __download_supported_file():
    """
    Download and return the lines of the supported file.

    Returns:
        list[str]: The list of lines of the supported file, excluding the
        header.
    """
    logging.info("Downloading codestreams file")

    if SUSE_CERT.exists():
        req = requests.get(SUPPORTED_CS_URL, verify=SUSE_CERT, timeout=15)
    else:
        req = requests.get(SUPPORTED_CS_URL, timeout=15)

    # exit on error
    req.raise_for_status()

    # Skip file header and empty lines
    return [line.decode('utf-8').strip() for line in req.iter_lines() if line][1:]

