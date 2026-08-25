#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [--output-root PATH]

Build and run the deterministic native Linux conditional-output ASan/UBSan gate.
EOF
}

OUTPUT_ROOT="out/artifacts/conditional_output_sanitizer"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      [[ $# -ge 2 && -n "$2" ]] || { usage >&2; exit 2; }
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[SANITIZER-GATE][ERROR] native Linux is required" >&2
  exit 2
fi
for command_name in gcc python3 sha256sum cmp; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "[SANITIZER-GATE][ERROR] missing command: $command_name" >&2
    exit 2
  }
done

STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUT_DIR="$OUTPUT_ROOT/$STAMP"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.env"
RESULTS="$OUT_DIR/scenario-sha256.tsv"
EXTENDED_EXPECTED="testdata/bench/conditional_output/sanitizer-expected-sha256.tsv"
RUNNER="$OUT_DIR/conditional_output_sanitizer"
NEGATIVE_RUNNER="$OUT_DIR/sanitizer_overlap_negative_probe"
SANITIZER_CFLAGS=(
  -std=c11 -O1 -g "-fsanitize=address,undefined" -fno-omit-frame-pointer
  -Wall -Wextra -Werror -DWC_WORKBUF_ENABLE_STATS -Iinclude
)
SANITIZER_ENV=(
  ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=1
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
)

fail_gate() {
  local message="$1"
  printf 'result=fail\nmessage=%s\nartifact_dir=%s\n' "$message" "$OUT_DIR" > "$SUMMARY"
  echo "[SANITIZER-GATE][ERROR] $message" >&2
  exit 1
}

{
  echo "compiler=$(gcc --version | head -n 1)"
  printf 'cflags='
  printf '%q ' "${SANITIZER_CFLAGS[@]}"
  echo
} > "$OUT_DIR/toolchain.txt"

if ! gcc "${SANITIZER_CFLAGS[@]}" \
    tools/dev/bench_conditional_output_harness.c \
    src/cond/header.c src/cond/title.c src/cond/grep.c src/cond/fold.c \
    src/core/workbuf.c -o "$RUNNER" > "$OUT_DIR/build.log" 2>&1; then
  fail_gate "positive harness build failed"
fi

if ! python3 tools/dev/bench_conditional_output.py \
    --runner "$RUNNER" \
    --repetitions 5 \
    --warmup 1 \
    --iterations-per-run 1 \
    --output-root "$OUT_DIR/frozen-matrix" \
    --target-architecture linux-x86_64 \
    --compiler gcc \
    --compiler-version "$(gcc -dumpfullversion -dumpversion)" \
    --cflags "${SANITIZER_CFLAGS[*]}" \
    --commit worktree \
    --source-version worktree \
    > "$OUT_DIR/frozen-matrix.log" 2>&1; then
  fail_gate "frozen 46-case matrix failed"
fi

printf 'scenario\tfixture\tsha256\n' > "$RESULTS"
for scenario in grep-line grep-line-cont; do
  for fixture in testdata/bench/conditional_output/*.txt; do
    fixture_id="$(basename "$fixture" .txt)"
    [[ "$fixture_id" == "stress" ]] && fixture_id="stress-crlf"
    first_out="$OUT_DIR/${scenario}-${fixture_id}-1.out"
    second_out="$OUT_DIR/${scenario}-${fixture_id}-2.out"
    if ! env "${SANITIZER_ENV[@]}" "$RUNNER" --scenario "$scenario" \
        --iterations 1 --fixture "$fixture" > "$first_out" \
        2> "$OUT_DIR/${scenario}-${fixture_id}-1.err"; then
      fail_gate "$scenario/$fixture_id sanitizer run failed"
    fi
    if ! env "${SANITIZER_ENV[@]}" "$RUNNER" --scenario "$scenario" \
        --iterations 1 --fixture "$fixture" > "$second_out" \
        2> "$OUT_DIR/${scenario}-${fixture_id}-2.err"; then
      fail_gate "$scenario/$fixture_id repeat sanitizer run failed"
    fi
    cmp -s "$first_out" "$second_out" || fail_gate "$scenario/$fixture_id output is non-deterministic"
    output_sha="$(sha256sum "$first_out" | awk '{print $1}')"
    expected_sha="$(awk -F '\t' -v case_id="$scenario/$fixture_id" \
      '$1 == case_id { sub(/\r$/, "", $2); print $2 }' "$EXTENDED_EXPECTED")"
    [[ -n "$expected_sha" ]] || fail_gate "$scenario/$fixture_id expected SHA is missing"
    [[ "$output_sha" == "$expected_sha" ]] || fail_gate "$scenario/$fixture_id frozen output mismatch"
    printf '%s\t%s\t%s\n' "$scenario" "$fixture_id" "$output_sha" >> "$RESULTS"
  done
done

[[ "$(wc -l < "$RESULTS")" -eq 19 ]] || fail_gate "extended scenario count mismatch"

if ! gcc "${SANITIZER_CFLAGS[@]}" -fno-builtin-memcpy \
    tools/test/sanitizer_overlap_negative_probe.c -o "$NEGATIVE_RUNNER" \
    > "$OUT_DIR/negative-build.log" 2>&1; then
  fail_gate "negative probe build failed"
fi

set +e
env "${SANITIZER_ENV[@]}" "$NEGATIVE_RUNNER" 1 \
  > "$OUT_DIR/negative.stdout" 2> "$OUT_DIR/negative.stderr"
negative_rc=$?
set -e
if [[ $negative_rc -eq 0 ]]; then
  fail_gate "negative probe unexpectedly succeeded"
fi
if ! grep -q 'AddressSanitizer: memcpy-param-overlap' "$OUT_DIR/negative.stderr"; then
  fail_gate "negative probe did not report memcpy-param-overlap"
fi

printf 'result=pass\npositive_cases=64\nfrozen_cases=46\nextended_cases=18\nnegative_probe=detected\nnegative_exit=%s\nartifact_dir=%s\n' \
  "$negative_rc" "$OUT_DIR" > "$SUMMARY"
echo "[SANITIZER-GATE] PASS positive_cases=64 negative_probe=detected artifact_dir=$OUT_DIR"