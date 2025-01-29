# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2025 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com

import logging
import re
import requests
from pathlib import Path

from klpbuild.klplib.codestream import Codestream

SUPPORTED_CS_URL = "https://gitlab.suse.de/live-patching/sle-live-patching-data/raw/master/supported.csv"
SUSE_CERT = Path("/etc/ssl/certs/SUSE_Trust_Root.pem")

def download_supported_file():
    logging.info("Downloading codestreams file")

    if SUSE_CERT.exists():
        req = requests.get(SUPPORTED_CS_URL, verify=SUSE_CERT, timeout=15)
    else:
        req = requests.get(SUPPORTED_CS_URL, timeout=15)

    # exit on error
    req.raise_for_status()

    first_line = True
    codestreams = []
    for line in req.iter_lines():
        # skip empty lines
        if not line:
            continue

        # skip file header
        if first_line:
            first_line = False
            continue

        # remove the last two columns, which are dates of the line
        # and add a fifth field with the forth one + rpm- prefix, and
        # remove the build counter number
        full_cs, proj, kernel_full, _, _ = line.decode("utf-8").strip().split(",")

        kernel = re.sub(r"\.\d+$", "", kernel_full)

        # MICRO releases contain project/patchid format
        if "/" in proj:
            proj, patchid = proj.split("/")
        else:
            patchid = ""

        codestreams.append(Codestream.from_codestream(full_cs, proj, patchid,
                                                      kernel))

    return codestreams
