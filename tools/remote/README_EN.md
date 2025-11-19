# Git Bash remote static cross-compile & smoke tests (standalone whois repo)

This helper lets you fire a one-shot remote build from Windows Git Bash: upload sources (excluding .git and dist/out) → remote static multi-arch build → optional QEMU smoke tests → fetch artifacts back → optionally sync into lzispro → remote cleanup.

- Local launcher: `whois/tools/remote/remote_build_and_test.sh`
- Remote builder: `whois/tools/remote/remote_build.sh`

> Note: the older PowerShell launcher is no longer maintained; prefer this Git Bash version.

## Prerequisites

Local (Windows)
- Git Bash with ssh/scp/tar available
- Prefer ssh-agent, or have a private key ready (e.g., `/d/xxx/id_rsa`)

Remote (Ubuntu VM)
- musl cross-compilers installed (script autodetects these default paths):
  - aarch64: `~/.local/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc`
  - armv7: `~/.local/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc`
  - x86_64: `~/.local/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc`
  - x86(i686): `~/.local/i686-linux-musl-cross/bin/i686-linux-musl-gcc`
  - mipsel: `~/.local/mipsel-linux-musl-cross/bin/mipsel-linux-musl-gcc`
  - mips64el: `~/.local/mips64el-linux-musl-cross/bin/mips64el-linux-musl-gcc`
  - loongarch64: `~/.local/loongson-gnu-toolchain-.../loongarch64-linux-gnu-gcc`
- Optional: `upx` (compress aarch64/x86_64), `qemu-user-static` (smoke tests), `file` (report binaries)

## Quick start

Default: build only (no QEMU), no arguments required:

```bash
cd /d/LZProjects/whois
./tools/remote/remote_build_and_test.sh
```

Specify a private key (single positional arg, same as -k; quote if path has spaces):

```bash
./tools/remote/remote_build_and_test.sh "/d/Larson/id_rsa"
```

Enable QEMU smoke tests (-r 1):

```bash
./tools/remote/remote_build_and_test.sh -r 1
```

Build only a subset of targets (faster):

```bash
./tools/remote/remote_build_and_test.sh -t "aarch64 x86_64 loongarch64"
```

Sync into the lzispro binary-only folder (e.g., `D:/LZProjects/lzispro/release/lzispro/whois`) and optionally prune non-whois-* files:

```bash
./tools/remote/remote_build_and_test.sh -s "/d/LZProjects/lzispro/release/lzispro/whois" -P 1
```

On completion, artifacts are fetched into `out/artifacts/<timestamp>/build_out/`, including:
- Per-arch binaries: `whois-<arch>` (7 arches: `aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64`)
- `file_report.txt` (summary of `file` output)
- `smoke_test.log` (if `-r 1` was used)

## Options

- `-H <host>`: SSH host (default `10.0.0.199`)
- `-u <user>`: SSH user (default `larson`)
- `-p <port>`: SSH port (default `22`)
- `-k <key>`: SSH private key path (optional; can rely on ssh-agent)
- `-R <remote_dir>`: remote working root (default `$HOME/whois_remote`)
- `-t <targets>`: space-separated target list (default `"aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64"`)
- `-r <0|1>`: whether to run QEMU smoke tests (default `0`)
- `-o <output_dir>`: remote output directory (default `out/build_out`)
- `-f <fetch_to>`: local artifacts base directory (default `out/artifacts`)
- `-s <sync_to>`: local sync directory (can point to `lzispro/.../whois` to keep binaries only)
- `-P <0|1>`: with `-s`, whether to prune non `whois-*` files before copying (default `0`)
- `[keyfile]`: single positional argument, shortcut for `-k`

You can also override most defaults via environment variables (`SSH_HOST` / `SSH_USER` / etc.).

## Workflow (short)

- SSH non-interactive: `StrictHostKeyChecking=accept-new`, `UserKnownHostsFile=/dev/null`, `BatchMode=yes`, `LogLevel=ERROR`.
- Remote base: `$HOME/whois_remote/src` by default; override via `-R`.
- Upload: tar streaming (excludes `.git`, `out/artifacts`, `dist`).
- Remote build: `tools/remote/remote_build.sh` static build (`-O3 -s -pthread`), loongarch64 uses `-static-libgcc -static-libstdc++`.
- QEMU: optional per-binary smoke tests (default mode = real network `net`):
  - Default query: `8.8.8.8`.
  - Override via `SMOKE_QUERIES` (space separated, e.g., `SMOKE_QUERIES="8.8.8.8 example.com"`).
  - `SMOKE_MODE` is kept for backward compatibility, default `net`; it no longer rewrites public addrs to private ones.
  - When `CFLAGS_EXTRA` contains `-DWHOIS_LOOKUP_SELFTEST` and `SMOKE_ARGS` contains `--selftest`, the smoke log will include extra `[LOOKUP_SELFTEST]` and `[DNS-HEALTH]` lines for DNS/lookup behaviour eyeballing; these outputs are meant for human inspection, not for strict machine parsing or production release configs.
- Fetch: copy remote `out/build_out` into local `out/artifacts/<timestamp>/build_out`.
- Optional sync: if `-s` is set, copy whois-* binaries into the provided directory (with optional `-P 1` pruning).
- Cleanup: remove the remote temp directory at the end.

## FAQ & tips

- Private key path with spaces: wrap it in quotes (and use forward slashes in Git Bash paths).
- `not found` for an arch: toolchain for that arch is missing or at a different path; restrict `-t` to installed targets.
- Empty `smoke_test.log`: either `-r 1` wasn’t used, or the remote host lacks `qemu-*-static`.
- `smoke_test.log` lines such as `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` / `[LOOKUP_SELFTEST]` are expected and correspond to DNS candidate/fallback paths, cache counters, health tracking and selftest summaries; when debugging DNS/connectivity issues, grep for these tags first.
- Static link failures usually mean platform/lib limitations; fall back to a local dynamic build (`make`) or adjust toolchains.

---

To speed up builds you can trim default targets down to e.g. `aarch64 x86_64`, or point `-s` to any other binary sink directory you prefer.
