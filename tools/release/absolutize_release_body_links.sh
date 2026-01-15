#!/usr/bin/env bash
set -euo pipefail

# absolutize_release_body_links.sh
# 将 release body 中的相对仓库路径链接（release/lzispro/whois/<asset>）
# 转换为 GitHub Release 下载直链：https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>
#
# 用法：
#   ./tools/release/absolutize_release_body_links.sh [-t v3.2.6] [-o owner] [-p repo] [--also-gnu] [--also-checksums] [-n] <file...>
# 说明：
#   -t/--tag           目标版本 tag（如 v3.2.6）。若省略且仅传入 1 个文件：
#                      将尝试从“文件名（如 v3.2.6.md）或正文（如 whois v3.2.6 / releases/.../v3.2.6）”推断。
#   -o/--owner         仓库 owner（默认：larsonzh）
#   -p/--repo          仓库名（默认：whois）
#   --also-gnu         可选：同时将 whois-x86_64-gnu 也绝对化
#   --also-checksums   可选：同时将 SHA256SUMS.txt 也绝对化
#   file...            一个或多个 .md 文件路径
#
# 仅匹配 9 个静态全静态二进制：
#   whois-x86_64 whois-x86 whois-aarch64 whois-armv7 whois-mipsel whois-mips64el whois-loongarch64 whois-win64.exe whois-win32.exe

owner=larsonzh
repo=whois
tag=""
also_gnu=0
also_checksums=0
dry_run=0

die() { echo "[absolutize] $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tag) tag="$2"; shift 2;;
    -o|--owner) owner="$2"; shift 2;;
    -p|--repo) repo="$2"; shift 2;;
    --also-gnu) also_gnu=1; shift;;
    --also-checksums) also_checksums=1; shift;;
    -n|--dry-run) dry_run=1; shift;;
    -h|--help) sed -n '1,40p' "$0"; exit 0;;
    --) shift; break;;
    -*) die "未知参数: $1";;
    *) break;;
  esac
done

[[ $# -gt 0 ]] || die "请至少指定一个要处理的 .md 文件"

# 若未显式提供 -t，且仅处理单个文件，尝试自动推断 tag
if [[ -z "$tag" && $# -eq 1 ]]; then
  f_candidate="$1"
  bn_candidate="$(basename -- "$f_candidate")"
  # 1) 文件名中查找 vX.Y.Z
  inferred_tag="$(printf '%s' "$bn_candidate" | grep -o -E 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
  if [[ -z "$inferred_tag" && -f "$f_candidate" ]]; then
    # 2) 正文中的 /releases/(download|tag)/vX.Y.Z
    inferred_tag="$(grep -o -E '/releases/(download|tag)/(v[0-9]+\.[0-9]+\.[0-9]+)' "$f_candidate" | head -n1 | sed -E 's#.*/(v[0-9]+\.[0-9]+\.[0-9]+).*#\1#' || true)"
  fi
  if [[ -z "$inferred_tag" && -f "$f_candidate" ]]; then
    # 3) 正文标题中的 "whois vX.Y.Z"
    inferred_tag="$(grep -o -E '\bwhois[[:space:]]+(v[0-9]+\.[0-9]+\.[0-9]+)\b' "$f_candidate" | head -n1 | sed -E 's#.*\b(v[0-9]+\.[0-9]+\.[0-9]+)\b.*#\1#' || true)"
  fi
  if [[ -n "$inferred_tag" ]]; then
    tag="$inferred_tag"
    echo "[absolutize] inferred tag: $tag (from ${bn_candidate:+filename/content})"
  fi
fi

[[ -n "$tag" ]] || die "必须指定 -t/--tag，或在仅处理单文件时可由文件名/正文自动推断（例如 v3.2.6）"

base="https://github.com/${owner}/${repo}/releases/download/${tag}"

# 要处理的资产名（9 个静态二进制）
assets=(
  whois-x86_64
  whois-x86
  whois-aarch64
  whois-armv7
  whois-mipsel
  whois-mips64el
  whois-loongarch64
  whois-win64.exe
  whois-win32.exe
)

gnu_asset="whois-x86_64-gnu"
checksum_file="SHA256SUMS.txt"

for f in "$@"; do
  [[ -f "$f" ]] || die "文件不存在: $f"

  tmp="${f}.tmp.$$"
  cp "$f" "$tmp"

  # 9 个静态二进制：release/lzispro/whois/<asset> -> ${base}/<asset>
  # 修正：原模式使用 \s（GNU sed BRE 不支持），导致无法匹配；改用 -E 扩展正则并移除多余空白匹配。
  for a in "${assets[@]}"; do
    if [[ $dry_run -eq 1 ]]; then
      cnt=$(grep -o -F "(release/lzispro/whois/${a})" "$tmp" | wc -l | tr -d ' ')
      echo "[absolutize][dry-run] ${f}: ${a} -> ${base}/${a} (matches: ${cnt})"
    else
      # 匹配形如 "[whois-aarch64](release/lzispro/whois/whois-aarch64)" 的括号
      sed -E -i "s#\\]\(release/lzispro/whois/${a}\\)#](${base}/${a})#g" "$tmp"
    fi
  done

  if [[ $also_gnu -eq 1 ]]; then
    if [[ $dry_run -eq 1 ]]; then
      cnt=$(grep -o -F "(release/lzispro/whois/${gnu_asset})" "$tmp" | wc -l | tr -d ' ')
      echo "[absolutize][dry-run] ${f}: ${gnu_asset} -> ${base}/${gnu_asset} (matches: ${cnt})"
    else
      sed -E -i "s#\\]\(release/lzispro/whois/${gnu_asset}\\)#](${base}/${gnu_asset})#g" "$tmp"
    fi
  fi

  if [[ $also_checksums -eq 1 ]]; then
    if [[ $dry_run -eq 1 ]]; then
      cnt=$(grep -o -F "(release/lzispro/whois/${checksum_file})" "$tmp" | wc -l | tr -d ' ')
      echo "[absolutize][dry-run] ${f}: ${checksum_file} -> ${base}/${checksum_file} (matches: ${cnt})"
    else
      sed -E -i "s#\\]\(release/lzispro/whois/${checksum_file}\\)#](${base}/${checksum_file})#g" "$tmp"
    fi
  fi
  if [[ $dry_run -eq 1 ]]; then
    rm -f "$tmp"
    echo "[absolutize] 预览完成（未改动）: $f"
  else
    mv "$tmp" "$f"
    echo "[absolutize] 已处理: $f"
  fi
done

echo "[absolutize] 完成：tag=${tag}, repo=${owner}/${repo}"
