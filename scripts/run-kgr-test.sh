#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

set -eo pipefail

LPS=" -r built "

if [ "$1" == "--no-lp" ]; then
	LPS=""
fi

# This script is bundled together in the directory of tests, so the parent
# directory of the current script is the bsc number
bsc=$(basename "$(pwd)")

# Remove any previous test output
rm -rf tests.out/*

# If the test has multiple files, it should be contained in a directory under
# repro/$bsc, otherwise it's only one file under repro
TEST_SCRIPT=repro/${bsc}_test_script.sh
CONF_IN=repro/${bsc}_config.in
if [ -d "repro/$bsc" ]; then
	TEST_SCRIPT=repro/${bsc}/test_script.sh
	CONF_IN=repro/$bsc/config.in
fi

if [ ! -f "$TEST_SCRIPT" ]; then
	echo "Missing $TEST_SCRIPT. Aborting."
	exit 1
fi

# Check multiple places where an updated version of the VMs can be found
for VMSDIR in "$(realpath ../kgr-test/vms)" "$HOME/klp/kgr-test/vms" "$HOME/kgr-test/vms" "$HOME/vms" "/home/nstange/vms"; do
	if [ -d "$VMSDIR" ]; then
		echo "Using VMS from $VMSDIR"
		break
	fi
done

if [ ! -d "$VMSDIR" ]; then
	echo "Missing VMs directory. Aborting."
	exit 1
fi

# grab all vm.xml files regarding each main codestream
xmls=""
cs_list=""
codestreams=$(cut -d _ -f 1 < "$CONF_IN" | uniq | tr '[:upper:]' '[:lower:]')
for cs in $codestreams; do
	xmls="$xmls -q $VMSDIR/$cs.xml"
	cs_list="$cs $cs_list"
done

# ppc64 and s390 can be flaky if too many processes are triggered
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
	JOBS=6
else
	JOBS=1
fi

for KGR_TEST_PATH in "$(realpath ../kgr-test/)" "$HOME/klp/kgr-test/" "/home/nstange/kgr-test"; do
	if [ -d "$KGR_TEST_PATH" ]; then
		echo "Using kgr-test from $KGR_TEST_PATH"
		break
	fi
done

if [ ! -d "$KGR_TEST_PATH" ]; then
	echo "kgr-test missing. Aborting."
	exit 1
fi

# Create scratch is doesn't exists
mkdir -p ~/scratch

echo "Running tests for codestreams: $cs_list"

"$KGR_TEST_PATH/kgr-test/kgr-test.py" -s ~/scratch/ \
		$LPS \
		-o tests.out \
		-t repro \
		$xmls \
		-j $JOBS 2>&1 | tee testall.out
