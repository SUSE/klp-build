import os
from pathlib import Path
import shutil
import sys

sys.path.append('..')
from lp_setup import Setup

SETUP_ARGS = {
    'bsc' : '9999999',
    'filter' : '',
    'cve' : '1234-5678',
    'cs' : '',
    'file_funcs' : [],
    'mod_file_funcs' : [],
    'conf_mod_file_funcs' : [],
    'module' : 'vmlinux',
    'conf' : '',
    'archs': ['x86_64', 'ppc64le', 's390x']
}

# default setup args
def sargs():
    return SETUP_ARGS.copy()

def basedir(v):
    return Path(os.getenv('KLP_WORK_DIR', ''), f'bsc{v["bsc"]}')

def setup(dargs, init = False):
    shutil.rmtree(basedir(dargs), ignore_errors=True)

    s = Setup(*tuple(dargs.values()))
    if init:
        s.setup_project_files()

    return s
