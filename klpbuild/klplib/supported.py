# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

from pathlib import Path
import copy
import logging
import re
import requests

from klpbuild.klplib import utils
from klpbuild.klplib.codestream import Codestream

SUPPORTED_CS_URL = "https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv"
SUSE_CERT = Path("/etc/ssl/certs/SUSE_Trust_Root.pem")

__supported_codestreams_cache = []

def get_supported_codestreams():
    """
    Download and parse the list of supported codestreams.

    Returns:
        list[Codestream]: A list of supported codestreams.
    """
    global __supported_codestreams_cache

    # Return cached list if present
    if __supported_codestreams_cache:
        return copy.deepcopy(__supported_codestreams_cache)

    __supported_codestreams_cache = []
    lines = __download_supported_file() if not utils.in_test_mode() else __load_supported_file()

    for line in lines:
        # remove the last two columns, which are dates of the line
        # and add a fifth field with the forth one + rpm- prefix, and
        # remove the build counter number
        full_cs, proj, kernel_full, _, _ = line.split(",")

        kernel = re.sub(r"\.\d+$", "", kernel_full)

        # MICRO releases contain project/patchid format
        patchid = ""
        if "/" in proj:
            proj, patchid = proj.split("/")

        cs = __codestream_from_supported(full_cs, proj, patchid, kernel)
        __supported_codestreams_cache.append(cs)

    return copy.deepcopy(__supported_codestreams_cache)


def __codestream_from_supported(cs, proj, patchid, kernel):
    # Parse SLE15-SP2_Update_25 to 15.2u25
    rt = "rt" if "-RT" in cs else ""
    sp = "0"
    update = "0"

    # SLE12-SP5_Update_51
    if "SLE" in cs:
        sle, _, update = cs.replace("SLE", "").replace("-RT", "").split("_")
        if "-SP" in sle:
            sle, sp = sle.split("-SP")
    # MICRO-6-0_Update_2
    elif "MICRO" in cs:
        sle, sp, update = cs.replace("MICRO-", "").replace("-RT", "").replace("_Update_", "-").split("-")
        if rt and int(update) >= 5:
            kernel = kernel + "-rt"
    else:
        assert False, "codestream name should contain either SLE or MICRO!"

    cs_name = f"{sle}.{sp}{rt}u{update}"
    return Codestream(cs_name, proj, patchid, kernel)


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
    logging.debug("Downloading codestreams file")

    if SUSE_CERT.exists():
        req = requests.get(SUPPORTED_CS_URL, verify=SUSE_CERT, timeout=15)
    else:
        req = requests.get(SUPPORTED_CS_URL, timeout=15)

    # exit on error
    req.raise_for_status()

    # Skip file header and empty lines
    return [line.decode('utf-8').strip() for line in req.iter_lines() if line][1:]
