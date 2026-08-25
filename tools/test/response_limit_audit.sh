#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date +%Y%m%d-%H%M%S)"
artifact_dir="${repo_root}/out/artifacts/response_limit_audit/${timestamp}"
binary="${artifact_dir}/response_limit_audit"
classification_binary="${artifact_dir}/response_limit_classification_audit"
report="${artifact_dir}/report.txt"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf '%s\n' '[RESPONSE-LIMIT-AUDIT] status=SKIP reason=native-linux-required' >&2
    exit 2
fi

mkdir -p "${artifact_dir}"

gcc -std=c11 -Wall -Wextra -Werror -O2 -ffunction-sections -fdata-sections \
    -I"${repo_root}/include" \
    "${repo_root}/tools/test/response_limit_audit.c" \
    "${repo_root}/src/core/net.c" \
    -Wl,--gc-sections -pthread -o "${binary}"

gcc -std=c11 -Wall -Wextra -Werror -O2 -ffunction-sections -fdata-sections \
    -I"${repo_root}/include" -I"${repo_root}/src/core" \
    "${repo_root}/tools/test/response_limit_classification_audit.c" \
    "${repo_root}/src/core/redirect.c" "${repo_root}/src/core/lookup_text.c" \
    -Wl,--gc-sections -o "${classification_binary}"

{
    "${binary}"
    "${classification_binary}"
} | tee "${report}"
printf '[RESPONSE-LIMIT-AUDIT] artifact=%s\n' "${artifact_dir}"