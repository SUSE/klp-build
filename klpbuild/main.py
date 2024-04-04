# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

import os
import sys

from klpbuild.cmd import main_func


def main():
    main_func(sys.argv[1:])


if __name__ == "__main__":
    main()
