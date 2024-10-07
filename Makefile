# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

all: ksrc extract utils templ

test:
	python3 -m unittest -v

setup:
	python3 -m unittest -v tests.test_lp_setup.LpSetupTest

extract:
	pytest tests/test_extract.py

templ:
	pytest tests/test_templ.py

ksrc:
	pytest tests/test_ksrc.py

utils:
	pytest tests/test_utils.py
