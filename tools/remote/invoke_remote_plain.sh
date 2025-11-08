#!/usr/bin/env bash
set -euo pipefail
# Plain validation run: no fold/grep so golden contract holds.
unset SMOKE_ARGS
export SMOKE_QUERIES="8.8.8.8 1.1.1.1"
./tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k "/c/Users/妙妙呜/.ssh/id_rsa" -r 1 -P 1 -Y 1 -G 1
