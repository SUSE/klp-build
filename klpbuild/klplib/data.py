# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Authors: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import logging

from klpbuild.klplib.utils import classify_codestreams_str
from klpbuild.klplib.ibs import download_cs_rpms


def download_missing_cs_data(codestreams):
    cs_to_download = __get_cs_missing_data(codestreams)
    download_cs_data(cs_to_download)


def download_cs_data(codestreams):
    logging.info("Download the necessary data from the following codestreams: %s",
                 classify_codestreams_str(codestreams))
    download_cs_rpms(codestreams)
    logging.info("Done.")


def __get_cs_missing_data(codestreams):
    return [cs for cs in codestreams if __is_cs_data_missing(cs)]


def __is_cs_data_missing(cs):
    return not cs.get_boot_file("config").exists()
