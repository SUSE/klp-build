#!/bin/bash

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
CONF_IN=repro/$bsc/config.in
if [ ! -f "$CONF_IN" ]; then
	CONF_IN=repro/${bsc}_config.in
fi

# On kunlun we are using Nicolai's vm files
VMSDIR="$HOME/vms"
if [ ! -d "$VMSDIR" ]; then
	VMSDIR="/dev/shm/nstange/vms"
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

~/kgr-test/kgr-test/kgr-test.py -s ~/scratch/ \
					$LPS \
					-o tests.out \
					-t repro \
					$xmls \
					-j $JOBS 2>&1 | tee testall.out
