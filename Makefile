# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>

test:
	python3 -m unittest -v

setup:
	python3 -m unittest -v tests.test_lp_setup.LpSetupTest

ccp:
	python3 -m unittest -v tests.test_ccp.CcpTesting

templ:
	python3 -m unittest -v tests.test_templ.TemplTesting

ksrc:
	pytest tests/test_ksrc.py
