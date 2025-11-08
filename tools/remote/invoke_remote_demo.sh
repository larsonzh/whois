#!/usr/bin/env bash
set -euo pipefail
# Helper wrapper to avoid Windows PowerShell quoting issues for multi-word args.
export SMOKE_ARGS="--fold --fold-unique -g 'netname|OrgName'"
export SMOKE_QUERIES="8.8.8.8 1.1.1.1"
# Pass through core remote build arguments; adjust SSH key path as needed.
./tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k "/c/Users/妙妙呜/.ssh/id_rsa" -r 1 -P 1 -Y 1 -G 1
