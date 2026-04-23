# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Authors: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import logging
import shutil

from klpbuild.klplib.utils import classify_codestreams_str,ARCHS
from klpbuild.klplib.ibs import download_cs_rpms
from klpbuild.klplib.config import get_user_path
from klpbuild.klplib.kernel_tree import  cleanup_obsolete_trees

def filter_obsolete_directories(target_path, valid_kerns):
    """
    check the path including the kernel version is valid or not
    """
    ret_paths = []

    if not target_path.exists():
        return []

    # Iterate through subdirectories/files in the target path
    for item in target_path.iterdir():
        item_str = item.name # Use the name of the folder, not the full path string

        # Check if any valid kernel version string exists within this folder name
        is_valid = any(k in item_str for k in valid_kerns)
        if not is_valid:
            ret_paths.append(item)

    return ret_paths

def cleanup_obsolete_data(valid_codestreams):
    """
    Remove obsolete rpm packages and extracted sources
    """
    obsolete_paths = []

    valid_kerns = [cs.kernel for cs in valid_codestreams]
    # The paths we going through:
    # $data_dir/kernel-rpms
    # $data_dir/$arch/boot/
    # $data_dir/$arch/lib/modules
    # $data_dir/$arch/usr/lib/modules

    data_dir = get_user_path("data_dir")
    for arch in ARCHS:
        for d in ["boot", "lib/modules", "usr/lib/modules"]:
            dest_dir = data_dir/arch/d
            if dest_dir.exists():
                obsolete_paths.extend(filter_obsolete_directories(dest_dir, valid_kerns))
    # check the special dir
    rpm_dir = data_dir/"kernel-rpms"
    if rpm_dir.exists():
        obsolete_paths.extend(filter_obsolete_directories(rpm_dir, valid_kerns))

    # do the cleanup
    for p in obsolete_paths:
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink() # Delete file if it's an RPM and not a directory
            logging.info("Removed obsolete path: %s", p)
        except OSError as e:
            logging.error("Error removing %s: %s", p, e)

    cleanup_obsolete_trees(valid_codestreams)


def download_missing_cs_data(codestreams):
    cs_to_download = __get_cs_missing_data(codestreams)
    if cs_to_download:
        download_cs_data(cs_to_download)


def download_cs_data(codestreams):
    logging.info("Download the necessary data from the following codestreams: %s",
                 classify_codestreams_str(codestreams))
    download_cs_rpms(codestreams)
    logging.info("Done.")


def __get_cs_missing_data(codestreams):
    return [cs for cs in codestreams if not cs.get_mod_path().exists()]
