#!/usr/bin/env bash
# Wrapper to pass multiple -D macros safely to remote_build_and_test.sh
# Enables GREP & SECLOG selftests plus redirect/fold tests.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.." || exit 1
./tools/remote/remote_build_and_test.sh -r 1 -P 1 -q 8.8.8.8 -a "--selftest" -E "-DWHOIS_GREP_TEST -DWHOIS_SECLOG_TEST" "$@"
