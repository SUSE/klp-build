#!/usr/bin/env bash

set -x

for f in $(git ls-files|grep '.*py$'); do
    reorder-python-imports "$f"
done
