#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -x

for f in $(git ls-files|grep '.*py$'); do
    reorder-python-imports "$f"
done
