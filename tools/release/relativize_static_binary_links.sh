#!/usr/bin/env bash
set -euo pipefail

# relativize_static_binary_links.sh
# 将 release body 中 7 个静态二进制的 GitHub Release 直链
#   https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>
# 转换为仓库内相对路径：release/lzispro/whois/<asset>
#
# 用法：
#   ./tools/release/relativize_static_binary_links.sh [--also-gnu] [--also-checksums] <file...>
# 说明：
#   默认仅处理 7 个静态二进制：
#   whois-x86_64 whois-x86 whois-aarch64 whois-armv7 whois-mipsel whois-mips64el whois-loongarch64
#   加 --also-gnu        可同时处理 whois-x86_64-gnu
#   加 --also-checksums  可同时处理 SHA256SUMS.txt

die() { echo "[relativize] $*" >&2; exit 1; }

also_gnu=0
also_checksums=0

args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --also-gnu) also_gnu=1; shift;;
    --also-checksums) also_checksums=1; shift;;
    -h|--help) sed -n '1,60p' "$0"; exit 0;;
    --) shift; break;;
    -*) die "未知参数: $1";;
    *) args+=("$1"); shift;;
  esac
done

set -- "${args[@]}" "$@"

[[ $# -gt 0 ]] || die "请至少指定一个要处理的 .md 文件"

assets=(
  whois-x86_64
  whois-x86
  whois-aarch64
  whois-armv7
  whois-mipsel
  whois-mips64el
  whois-loongarch64
)

extra_targets=()
[[ $also_gnu -eq 1 ]] && extra_targets+=(whois-x86_64-gnu)
[[ $also_checksums -eq 1 ]] && extra_targets+=(SHA256SUMS.txt)

targets=("${assets[@]}" "${extra_targets[@]}")

for f in "$@"; do
  [[ -f "$f" ]] || die "文件不存在: $f"

  tmp="${f}.tmp.$$"
  cp "$f" "$tmp"

  # 使用 GNU sed 扩展正则（Git Bash/Ubuntu 皆可）。匹配形如：
  #   [whois-x86_64](https://github.com/larsonzh/whois/releases/download/v3.2.5/whois-x86_64)
  # 可容忍 http/https、任意 owner/repo、任意 tag。
  # 之前版本因使用 BRE + \? 失效，且 \s 在 BRE 中不生效，导致无法命中。
  # 新模式：https?:// 后接任意非右括号字符，直到 /releases/download/<tag>/<asset>)
  # 注意：不处理 glibc 与校验文件；按需扩展。

  for a in "${targets[@]}"; do
    # 处理可能的 CRLF：先统一行尾换行，再替换。
    sed -E -i "s#\]\(https?://[^)]*/releases/download/[^)]*/${a}\)#](release/lzispro/whois/${a})#g" "$tmp"
  done

  mv "$tmp" "$f"
  echo "[relativize] 已处理: $f"
done

echo "[relativize] 完成：替换静态二进制${also_gnu:+ + glibc}${also_checksums:+ + checksums}链接为相对路径。"
