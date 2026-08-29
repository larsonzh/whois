#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: proxy_tls_dependency_spike.sh --target NAME [--output-root PATH]

Environment:
  CC               Target C compiler (default: cc)
  OPENSSL_CFLAGS   Target OpenSSL include/compiler flags
  OPENSSL_LIBS     Target OpenSSL linker flags and libraries

The probe requires a fully static OpenSSL link with certificate and hostname
verification APIs. It does not run the target binary.
EOF
}

TARGET=""
OUTPUT_ROOT="out/artifacts/proxy_tls_dependency_spike"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 && -n "$2" ]] || { usage >&2; exit 2; }
      TARGET="$2"
      shift 2
      ;;
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

[[ -n "$TARGET" ]] || { usage >&2; exit 2; }
CC="${CC:-cc}"
command -v "$CC" >/dev/null 2>&1 || {
  echo "[PROXY-TLS-SPIKE] result=unavailable target=$TARGET reason=compiler-not-found" >&2
  exit 2
}

read -r -a openssl_cflags <<< "${OPENSSL_CFLAGS:-}"
read -r -a openssl_libs <<< "${OPENSSL_LIBS:-}"
[[ ${#openssl_libs[@]} -gt 0 ]] || {
  echo "[PROXY-TLS-SPIKE] result=unavailable target=$TARGET reason=openssl-libs-not-configured" >&2
  exit 2
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
artifact_dir="$repo_root/$OUTPUT_ROOT/$timestamp-$TARGET"
mkdir -p "$artifact_dir"
source_file="$artifact_dir/probe.c"
binary="$artifact_dir/proxy-tls-probe"
report="$artifact_dir/report.env"

cat > "$source_file" <<'EOF'
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

int main(void)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return 1;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return 2;
    }
    if (SSL_set_tlsext_host_name(ssl, "proxy.example.test") != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 3;
    }
    X509_VERIFY_PARAM* params = SSL_get0_param(ssl);
    if (!params || X509_VERIFY_PARAM_set1_host(params, "proxy.example.test", 0) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 4;
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
EOF

{
  echo "target=$TARGET"
  echo "compiler=$CC"
  printf 'openssl_cflags='
  printf '%q ' "${openssl_cflags[@]}"
  echo
  printf 'openssl_libs='
  printf '%q ' "${openssl_libs[@]}"
  echo
} > "$artifact_dir/toolchain.txt"

if ! "$CC" -std=c11 -Wall -Wextra -Werror "${openssl_cflags[@]}" \
    "$source_file" -static -o "$binary" "${openssl_libs[@]}" \
    > "$artifact_dir/build.log" 2>&1; then
  printf 'result=unavailable\ntarget=%s\nreason=static-link-failed\n' "$TARGET" > "$report"
  echo "[PROXY-TLS-SPIKE] result=unavailable target=$TARGET reason=static-link-failed report=$report" >&2
  exit 2
fi

if command -v file >/dev/null 2>&1; then
  file "$binary" > "$artifact_dir/file.txt"
  if grep -Eqi 'dynamically linked|interpreter ' "$artifact_dir/file.txt"; then
    printf 'result=unavailable\ntarget=%s\nreason=dynamic-output\n' "$TARGET" > "$report"
    echo "[PROXY-TLS-SPIKE] result=unavailable target=$TARGET reason=dynamic-output report=$report" >&2
    exit 2
  fi
fi

printf 'result=pass\ntarget=%s\nbackend=openssl\nstatic_link=true\npeer_verify=true\nhostname_verify=true\nsni=true\n' \
  "$TARGET" > "$report"
echo "[PROXY-TLS-SPIKE] result=pass target=$TARGET report=$report"