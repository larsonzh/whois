#!/usr/bin/env bash
set -euo pipefail

# relativize_static_binary_links.sh
# 将 release body 中 7 个静态二进制的 GitHub Release 直链
#   https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>
# 转换为仓库内相对路径：release/lzispro/whois/<asset>
#
# 用法：
#   ./tools/release/relativize_static_binary_links.sh <file...>
# 说明：
#   仅处理 7 个静态二进制：
#   whois-x86_64 whois-x86 whois-aarch64 whois-armv7 whois-mipsel whois-mips64el whois-loongarch64
#   不影响 whois-x86_64-gnu 与 SHA256SUMS.txt（如需处理，请手动修改或扩展脚本）。

die() { echo "[relativize] $*" >&2; exit 1; }

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

  for a in "${assets[@]}"; do
    # 处理可能的 CRLF：先统一行尾换行，再替换。
    sed -E -i "s#\]\(https?://[^)]*/releases/download/[^)]*/${a}\)#](release/lzispro/whois/${a})#g" "$tmp"
  done

  mv "$tmp" "$f"
  echo "[relativize] 已处理: $f"
done

echo "[relativize] 完成：仅替换 7 个静态二进制的直链为相对路径。"
