#!/usr/bin/env bash
set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.8}"
INSTALL_ROOT="${OPENSSL_INSTALL_ROOT:-$HOME/.local/openssl-static}"
CACHE_ROOT="${OPENSSL_CACHE_ROOT:-$HOME/.cache/whois-openssl}"
TARGETS="${TARGETS:-aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64 win32 win64}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"
OPENSSL_SIGNING_FINGERPRINT="B146647E45A7B33947AB226B2A2C87D161692D40"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SPIKE="$REPO_ROOT/tools/test/proxy_tls_dependency_spike.sh"
RUN_ID="$(date -u +%Y%m%d-%H%M%S)"
ARTIFACT_ROOT="$REPO_ROOT/out/artifacts/proxy_tls_dependency_matrix/$RUN_ID"
DOWNLOAD_ROOT="$CACHE_ROOT/downloads"
SOURCE_ROOT="$CACHE_ROOT/sources"
BUILD_ROOT="$CACHE_ROOT/build/$OPENSSL_VERSION"
VERSION_ROOT="$INSTALL_ROOT/$OPENSSL_VERSION"
SOURCE_ARCHIVE="openssl-$OPENSSL_VERSION.tar.gz"
RELEASE_BASE="https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION"

log() { echo "[OPENSSL-STATIC] $*"; }
fail() { echo "[OPENSSL-STATIC][ERROR] $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: bootstrap_openssl_static.sh [--targets "TARGET ..."] [--jobs N]

Environment:
  OPENSSL_VERSION       Pinned OpenSSL release (default: 3.5.8)
  OPENSSL_INSTALL_ROOT  Versioned install root
  OPENSSL_CACHE_ROOT    Download, source, and build cache root
  TARGETS               Space-separated target set
  JOBS                  Parallel make jobs
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --targets)
      [[ $# -ge 2 && -n "$2" ]] || fail "--targets requires a value"
      TARGETS="$2"
      shift 2
      ;;
    --jobs)
      [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || fail "--jobs requires a positive integer"
      JOBS="$2"
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

for tool in curl gpg make perl tar sha256sum file readelf objdump pkg-config; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool not found: $tool"
done
[[ -x "$SPIKE" ]] || fail "TLS dependency spike is not executable: $SPIKE"

mkdir -p "$ARTIFACT_ROOT" "$DOWNLOAD_ROOT" "$SOURCE_ROOT" "$BUILD_ROOT" "$VERSION_ROOT"

download_release_file() {
  local name="$1"
  local destination="$DOWNLOAD_ROOT/$name"
  if [[ ! -s "$destination" ]]; then
    log "Downloading $name"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-all-errors \
      --retry-delay 2 --connect-timeout 20 --max-time 1200 --continue-at - \
      "$RELEASE_BASE/$name" -o "$destination.part"
    mv -f "$destination.part" "$destination"
  fi
}

download_release_file "$SOURCE_ARCHIVE"
download_release_file "$SOURCE_ARCHIVE.sha256"
download_release_file "$SOURCE_ARCHIVE.asc"

PUBKEYS="$DOWNLOAD_ROOT/pubkeys.asc"
if [[ ! -s "$PUBKEYS" ]]; then
  log "Downloading OpenSSL signing certificates"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 5 --retry-all-errors \
    --retry-delay 2 --connect-timeout 20 --max-time 120 --continue-at - \
    https://openssl-library.org/source/pubkeys.asc -o "$PUBKEYS.part"
  mv -f "$PUBKEYS.part" "$PUBKEYS"
fi

(
  cd "$DOWNLOAD_ROOT"
  sha256sum -c "$SOURCE_ARCHIVE.sha256"
) | tee "$ARTIFACT_ROOT/source-sha256.log"

GNUPGHOME="$ARTIFACT_ROOT/gnupg"
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
cp "$PUBKEYS" "$ARTIFACT_ROOT/pubkeys.asc"
gpg --batch --import "$PUBKEYS" >"$ARTIFACT_ROOT/gpg-import.log" 2>&1
gpg --batch --status-fd 1 --verify \
  "$DOWNLOAD_ROOT/$SOURCE_ARCHIVE.asc" "$DOWNLOAD_ROOT/$SOURCE_ARCHIVE" \
  >"$ARTIFACT_ROOT/gpg-status.log" 2>"$ARTIFACT_ROOT/gpg-verify.log"
grep -E "^\[GNUPG:\] VALIDSIG .*${OPENSSL_SIGNING_FINGERPRINT}([[:space:]]|$)" \
  "$ARTIFACT_ROOT/gpg-status.log" >/dev/null ||
  fail "release signature does not chain to the pinned OpenSSL signing fingerprint"

SOURCE_DIR="$SOURCE_ROOT/openssl-$OPENSSL_VERSION"
if [[ ! -f "$SOURCE_DIR/Configure" ]]; then
  rm -rf "$SOURCE_DIR"
  tar -xzf "$DOWNLOAD_ROOT/$SOURCE_ARCHIVE" -C "$SOURCE_ROOT"
fi
[[ -f "$SOURCE_DIR/LICENSE.txt" ]] || fail "OpenSSL license file not found"
cp "$SOURCE_DIR/LICENSE.txt" "$ARTIFACT_ROOT/OPENSSL-LICENSE.txt"
SOURCE_SHA256="$(sha256sum "$DOWNLOAD_ROOT/$SOURCE_ARCHIVE" | awk '{print $1}')"

resolve_compiler() {
  local target="$1"
  local candidates=()
  case "$target" in
    aarch64) candidates=("$HOME/.local/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc" aarch64-linux-musl-gcc) ;;
    armv7) candidates=("$HOME/.local/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc" arm-linux-musleabihf-gcc armv7l-linux-musleabihf-gcc) ;;
    x86_64) candidates=("$HOME/.local/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc" x86_64-linux-musl-gcc) ;;
    x86) candidates=("$HOME/.local/i686-linux-musl-cross/bin/i686-linux-musl-gcc" i686-linux-musl-gcc) ;;
    mipsel) candidates=("$HOME/.local/mipsel-linux-musl-cross/bin/mipsel-linux-musl-gcc" mipsel-linux-musl-gcc) ;;
    mips64el) candidates=("$HOME/.local/mips64el-linux-musl-cross/bin/mips64el-linux-musl-gcc" mips64el-linux-musl-gcc) ;;
    loongarch64) candidates=("$HOME/.local/loongarch64-linux-musl-cross/bin/loongarch64-linux-musl-gcc" loongarch64-linux-musl-gcc "$HOME/.local/loongson-gnu-toolchain-8.3-x86_64-loongarch64-linux-gnu-rc1.6/bin/loongarch64-linux-gnu-gcc" loongarch64-linux-gnu-gcc) ;;
    win32) candidates=("$HOME/.local/i686-w64-mingw32/bin/i686-w64-mingw32-gcc" i686-w64-mingw32-gcc) ;;
    win64) candidates=("$HOME/.local/x86_64-w64-mingw32/bin/x86_64-w64-mingw32-gcc" x86_64-w64-mingw32-gcc) ;;
    *) return 1 ;;
  esac

  local candidate resolved
  for candidate in "${candidates[@]}"; do
    if [[ "$candidate" = /* && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    resolved="$(command -v "$candidate" 2>/dev/null || true)"
    if [[ -n "$resolved" ]]; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done
  return 1
}

resolve_binutil() {
  local compiler="$1"
  local tool="$2"
  local compiler_dir compiler_name candidate
  compiler_dir="$(dirname "$compiler")"
  compiler_name="$(basename "$compiler")"
  candidate="$compiler_dir/${compiler_name%-gcc}-$tool"
  if [[ -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  candidate="${compiler_name%-gcc}-$tool"
  command -v "$candidate" 2>/dev/null
}

configure_target() {
  case "$1" in
    aarch64) echo linux-aarch64 ;;
    armv7) echo linux-armv4 ;;
    x86_64) echo linux-x86_64 ;;
    x86) echo linux-x86 ;;
    mipsel) echo linux-mips32 ;;
    mips64el) echo linux64-mips64 ;;
    loongarch64) echo linux64-loongarch64 ;;
    win32) echo mingw ;;
    win64) echo mingw64 ;;
    *) return 1 ;;
  esac
}

AVAILABLE_TARGETS="$ARTIFACT_ROOT/configure-targets.txt"
"$SOURCE_DIR/Configure" LIST > "$AVAILABLE_TARGETS"

SUMMARY="$ARTIFACT_ROOT/summary.tsv"
printf 'target\tresult\ttriplet\tconfigure_target\tprefix\treason\n' > "$SUMMARY"
overall_result=0

for target in $TARGETS; do
  target_artifact="$ARTIFACT_ROOT/$target"
  mkdir -p "$target_artifact"
  log "Building target=$target"

  compiler="$(resolve_compiler "$target" || true)"
  config="$(configure_target "$target" || true)"
  if [[ -z "$compiler" || -z "$config" ]]; then
    printf '%s\tfail\tunknown\t%s\t-\tcompiler-or-config-unavailable\n' "$target" "${config:-unknown}" >> "$SUMMARY"
    overall_result=1
    continue
  fi
  if ! grep -Fx "$config" "$AVAILABLE_TARGETS" >/dev/null; then
    printf '%s\tfail\t%s\t%s\t-\tconfigure-target-unavailable\n' \
      "$target" "$($compiler -dumpmachine)" "$config" >> "$SUMMARY"
    overall_result=1
    continue
  fi

  ar="$(resolve_binutil "$compiler" ar || true)"
  ranlib="$(resolve_binutil "$compiler" ranlib || true)"
  if [[ -z "$ar" || -z "$ranlib" ]]; then
    printf '%s\tfail\t%s\t%s\t-\tbinutils-unavailable\n' \
      "$target" "$($compiler -dumpmachine)" "$config" >> "$SUMMARY"
    overall_result=1
    continue
  fi
  rc=""
  if [[ "$target" == win32 || "$target" == win64 ]]; then
    rc="$(resolve_binutil "$compiler" windres || true)"
    if [[ -z "$rc" ]]; then
      printf '%s\tfail\t%s\t%s\t-\twindres-unavailable\n' \
        "$target" "$($compiler -dumpmachine)" "$config" >> "$SUMMARY"
      overall_result=1
      continue
    fi
  fi

  prefix="$VERSION_ROOT/$target"
  build_dir="$BUILD_ROOT/$target"
  rm -rf "$build_dir" "$prefix"
  mkdir -p "$build_dir" "$prefix"

  {
    echo "target=$target"
    echo "triplet=$($compiler -dumpmachine)"
    echo "compiler=$compiler"
    "$compiler" --version | head -1
    echo "ar=$ar"
    echo "ranlib=$ranlib"
    echo "rc=${rc:-none}"
    echo "configure_target=$config"
    echo "openssl_version=$OPENSSL_VERSION"
    echo "source_sha256=$SOURCE_SHA256"
    echo "configure_options=no-shared no-dso no-tests"
  } > "$target_artifact/build-manifest.env"

  if ! (
    cd "$build_dir"
    CC="$compiler" AR="$ar" RANLIB="$ranlib" RC="$rc" \
      "$SOURCE_DIR/Configure" "$config" \
      --prefix="$prefix" --openssldir="$prefix/ssl" \
      no-shared no-dso no-tests
  ) >"$target_artifact/configure.log" 2>&1; then
    printf '%s\tfail\t%s\t%s\t%s\tconfigure-failed\n' \
      "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
    overall_result=1
    continue
  fi
  cp "$build_dir/configdata.pm" "$target_artifact/configdata.pm"
  (
    cd "$build_dir"
    perl configdata.pm --dump
  ) > "$target_artifact/configdata.txt"

  if ! make -C "$build_dir" -j"$JOBS" >"$target_artifact/build.log" 2>&1; then
    printf '%s\tfail\t%s\t%s\t%s\tbuild-failed\n' \
      "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
    overall_result=1
    continue
  fi
  if ! make -C "$build_dir" install_sw >"$target_artifact/install.log" 2>&1; then
    printf '%s\tfail\t%s\t%s\t%s\tinstall-failed\n' \
      "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
    overall_result=1
    continue
  fi

  libssl="$(find "$prefix" -type f -name libssl.a -print -quit)"
  libcrypto="$(find "$prefix" -type f -name libcrypto.a -print -quit)"
  pkgconfig_dir="$(find "$prefix" -type d -path '*/pkgconfig' -print -quit)"
  if [[ -z "$libssl" || -z "$libcrypto" || -z "$pkgconfig_dir" ]]; then
    printf '%s\tfail\t%s\t%s\t%s\tinstalled-static-libraries-missing\n' \
      "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
    overall_result=1
    continue
  fi

  openssl_cflags="$(PKG_CONFIG_PATH='' PKG_CONFIG_LIBDIR="$pkgconfig_dir" pkg-config --cflags openssl)"
  openssl_libs="$(PKG_CONFIG_PATH='' PKG_CONFIG_LIBDIR="$pkgconfig_dir" pkg-config --static --libs openssl)"
  probe_root="out/artifacts/proxy_tls_dependency_matrix/$RUN_ID/probes/$target"
  if ! CC="$compiler" OPENSSL_CFLAGS="$openssl_cflags" OPENSSL_LIBS="$openssl_libs" \
      "$SPIKE" --target "$target" --output-root "$probe_root" \
      >"$target_artifact/probe.stdout.log" 2>"$target_artifact/probe.stderr.log"; then
    printf '%s\tfail\t%s\t%s\t%s\tstatic-probe-failed\n' \
      "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
    overall_result=1
    continue
  fi

  probe_dir="$(find "$REPO_ROOT/$probe_root" -mindepth 1 -maxdepth 1 -type d -print -quit)"
  probe_binary="$probe_dir/proxy-tls-probe"
  if [[ "$target" == win32 || "$target" == win64 ]]; then
    probe_binary="$probe_binary.exe"
  fi
  [[ -f "$probe_binary" ]] || {
    printf '%s\tfail\t%s\t%s\t%s\tprobe-binary-missing\n' \
      "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
    overall_result=1
    continue
  }

  file "$probe_binary" > "$target_artifact/file.txt"
  if [[ "$target" == win32 || "$target" == win64 ]]; then
    objdump -p "$probe_binary" > "$target_artifact/objdump.txt"
    if grep -Eqi 'DLL Name:.*(libssl|libcrypto)' "$target_artifact/objdump.txt"; then
      printf '%s\tfail\t%s\t%s\t%s\topenssl-dll-dependency\n' \
        "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
      overall_result=1
      continue
    fi
  else
    readelf -l "$probe_binary" > "$target_artifact/readelf-program.txt"
    readelf -d "$probe_binary" > "$target_artifact/readelf-dynamic.txt"
    if grep -Eq 'Requesting program interpreter|\(NEEDED\)' \
        "$target_artifact/readelf-program.txt" "$target_artifact/readelf-dynamic.txt"; then
      printf '%s\tfail\t%s\t%s\t%s\tdynamic-elf-dependency\n' \
        "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
      overall_result=1
      continue
    fi
  fi

  sha256sum "$libssl" "$libcrypto" "$probe_binary" > "$target_artifact/SHA256SUMS.txt"
  cat > "$target_artifact/openssl.spdx" <<EOF
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: whois-openssl-$OPENSSL_VERSION-$target
DocumentNamespace: https://github.com/larsonzh/whois/spdx/openssl-$OPENSSL_VERSION/$RUN_ID/$target
Creator: Tool: bootstrap_openssl_static.sh
Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)

PackageName: OpenSSL
SPDXID: SPDXRef-Package-OpenSSL
PackageVersion: $OPENSSL_VERSION
PackageDownloadLocation: $RELEASE_BASE/$SOURCE_ARCHIVE
FilesAnalyzed: false
PackageChecksum: SHA256: $SOURCE_SHA256
PackageLicenseConcluded: Apache-2.0
PackageLicenseDeclared: Apache-2.0
PackageCopyrightText: NOASSERTION
EOF

  printf '%s\tpass\t%s\t%s\t%s\t-\n' \
    "$target" "$($compiler -dumpmachine)" "$config" "$prefix" >> "$SUMMARY"
done

pass_count="$(awk -F '\t' 'NR > 1 && $2 == "pass" { count++ } END { print count + 0 }' "$SUMMARY")"
read -r -a requested_targets <<< "$TARGETS"
target_count="${#requested_targets[@]}"
{
  echo "run_id=$RUN_ID"
  echo "openssl_version=$OPENSSL_VERSION"
  echo "source_sha256=$SOURCE_SHA256"
  echo "signing_fingerprint=$OPENSSL_SIGNING_FINGERPRINT"
  echo "target_count=$target_count"
  echo "pass_count=$pass_count"
  echo "result=$([[ $overall_result -eq 0 && $pass_count -eq $target_count ]] && echo pass || echo fail)"
} > "$ARTIFACT_ROOT/report.env"

log "Summary: $SUMMARY"
cat "$SUMMARY"
if [[ $overall_result -ne 0 || $pass_count -ne $target_count ]]; then
  fail "one or more OpenSSL static targets failed"
fi
log "All $pass_count targets passed; report=$ARTIFACT_ROOT/report.env"