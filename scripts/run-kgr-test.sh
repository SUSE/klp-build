#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Marcos Paulo de Souza

LPS=" -r built "

if [ "$1" == "--no-lp" ]; then
	LPS=""
fi

# This script is bundled together in the directory of tests, so the parent
# directory of the current script is the bsc number
bsc=$(basename "$(pwd)")

TEST_SCRIPT="repro/${bsc}_test_script.sh"
if [ ! -f "$TEST_SCRIPT" ]; then
	echo "Missing $TEST_SCRIPT. Aborting."
	exit 1
fi

# Remove any previous test output
rm -rf tests.out/*

# If the test has multiple files, it should be contained in a directory under
# repro/$bsc, otherwise it's only one file under repro
CONF_IN=repro/$bsc/config.in
if [ ! -f "$CONF_IN" ]; then
	CONF_IN=repro/${bsc}_config.in
fi

# Check multiple places where an updated version of the VMs can be found
for VMSDIR in "$HOME/kgr-test/vms" "$HOME/vms" "/home/nstange/vms"; do
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
codestreams=$(cut -d _ -f 1 < "$CONF_IN" | uniq | tr '[:upper:]' '[:lower:]')
for cs in $codestreams; do
	xmls="$xmls -q $VMSDIR/$cs.xml"
done

# ppc64 and s390 can be flaky if too many processes are triggered
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
	JOBS=6
else
	JOBS=1
fi

KGR_TEST_PATH="$HOME/kgr-test/kgr-test/kgr-test.py"
if [ ! -f "$KGR_TEST_PATH" ]; then
	KGR_TEST_PATH="/home/nstange/kgr-test/kgr-test/kgr-test.py"
fi

# Create scratch is doesn't exists
mkdir -p ~/scratch

$KGR_TEST_PATH -s ~/scratch/ \
		$LPS \
		-o tests.out \
		-t repro \
		$xmls \
		-j $JOBS 2>&1 | tee testall.out
