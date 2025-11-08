#!/usr/bin/env bash
set -euo pipefail
# Selftest-only run: run built-in tests; do not perform golden verification.
export SMOKE_ARGS="--selftest"
export SMOKE_QUERIES="8.8.8.8"
./tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k "/c/Users/妙妙呜/.ssh/id_rsa" -r 1 -P 1 -Y 1 -G 0
