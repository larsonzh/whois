# whois Operations & Release Guide

Chinese version: `docs/OPERATIONS_CN.md`

This guide summarizes common day-to-day tasks: commit/push, remote cross-compilation + smoke tests, and publishing releases to GitHub and Gitee.

For link style conversion (absolute GitHub asset URLs ↔ relative repo paths) see: `docs/RELEASE_LINK_STYLE.md`.

---

## One-click release (Windows PowerShell)

Entry script: `tools/release/full_release.ps1` (wraps the Bash script `tools/release/full_release.sh`).

Common usage:

- Default release (auto-bump patch + networked smoke test)
  ```powershell
  .\tools\release\full_release.ps1
  ```
- Custom smoke queries (space separated)
  ```powershell
  .\tools\release\full_release.ps1 -Queries "8.8.8.8 1.1.1.1"
  ```
- Skip smoke tests (faster)
  ```powershell
  .\tools\release\full_release.ps1 -NoSmoke
  ```
- Specify tag explicitly (e.g., v3.2.0)
  ```powershell
  .\tools\release\full_release.ps1 -Tag v3.2.0
  ```
- Specify lzispro path (when not at the same level as whois)
  ```powershell
  .\tools\release\full_release.ps1 -LzisproPath "D:\\LZProjects\\lzispro"
  ```
- Dry run (print steps only)
  ```powershell
  .\tools\release\full_release.ps1 -DryRun -NoSmoke -Queries "8.8.8.8 1.1.1.1"
  ```

Artifacts and logs:
- Seven static binaries will be synced to: `<lzispro>/release/lzispro/whois/`
- Detailed log: `whois/out/release_flow/<timestamp>/step1_remote.log`
- Strict mode: warnings are treated as failures by default (STRICT_WARN=1)

---

## VS Code Tasks

- Git: Quick Push
- Remote: Build and Sync whois statics (one-click remote build and sync seven static binaries)

Inputs will prompt after running the task. The task syncs `whois-*` into your local `lzispro/release/lzispro/whois` directory and prunes non-whois files if `-P 1` is used.
# whois Operations & Release Guide

Chinese version: `docs/OPERATIONS_CN.md`


New task:
- One-Click Release (invokes `tools/release/one_click_release.ps1` to update GitHub/Gitee Release; optionally skip creating/pushing a tag; supports optional remote build + smoke + sync and push of static binaries)

Prompts when running One-Click Release:
- releaseVersion: plain version (no leading `v`), e.g. `3.2.5`. Used to read `docs/release_bodies/vX.Y.Z.md` and compute tag name.
- skipTag: whether to skip creating/pushing the tag (`true`/`false`).
 - buildSync: whether to perform "remote build + smoke + sync static binaries and commit/push" (default `true`).
 - Remote build args: `rbHost/rbUser/rbKey/rbSmoke/rbQueries/rbSmokeArgs/rbGolden/rbCflagsExtra/rbSyncDir`

Underlying command (PowerShell):
```powershell
  -Version <releaseVersion> -GithubName <releaseName> -GiteeName <releaseName> -SkipTagIf <skipTag> `
  -BuildAndSyncIf <buildSync> -RbHost <rbHost> -RbUser <rbUser> -RbKey '<rbKey>' `
  -RbSmoke <rbSmoke> -RbQueries '<rbQueries>' -RbSmokeArgs '<rbSmokeArgs>' -RbGolden <rbGolden> `
```

Notes:
- Tokens: GitHub requires `GH_TOKEN` or `GITHUB_TOKEN`; Gitee requires `GITEE_TOKEN`. Missing tokens are skipped with a warning.
- If `buildSync=false`, it will skip the remote build/smoke/sync-and-push phase and proceed to tag/release updates only.
- You can enable `WHOIS_DEBUG_SSH=1` to turn on `ssh -vvv` diagnostics inside the remote build script.

---

## Artifacts housekeeping

---
## Tag and publish (optional)

Script: `tools/dev/tag_release.ps1`

.\tools\dev\tag_release.ps1 -Tag v3.2.0 -Message "Release v3.2.0"
```

If you later want to switch those asset links to repository-relative paths for better access behind domestic mirrors, use `relativize_static_binary_links.sh` (see `docs/RELEASE_LINK_STYLE.md`).

### Re-create the same tag to refresh assets
Use this when you need to replace release assets (e.g., update to the latest static binaries) without changing the version (e.g., `v3.2.7`).

Steps:
2) Delete the local and remote tag:
  ```powershell
  git tag -d vX.Y.Z
  ```
3) Prepare the latest static artifacts (choose one):
  - Run the VS Code task “Remote: Build and Sync whois statics”; or
4) Re-create and push the same tag:
  ```powershell
  git tag -a vX.Y.Z -m "Release vX.Y.Z"
  ```
5) Wait for the release workflow to re-run and collect the 7 static binaries and `SHA256SUMS.txt` from this repo's `release/lzispro/whois/`.
6) If you only need to update the release body without changing the tag, run:
  ```powershell
  .\tools\release\one_click_release.ps1 -Version X.Y.Z -SkipTagIf true
  ```
Note: The release process is decoupled from the lzispro repository. Assets are sourced from this repo's `release/lzispro/whois/`, not from lzispro.

### New script: one_click_release.ps1
Path: `tools/release/one_click_release.ps1`

Purpose: one-click update of GitHub/Gitee Release body and display name; can optionally skip the tag creation/push (same behavior as the VS Code task).
Examples:
```powershell
# Create/push tag + update both releases
./tools/release/one_click_release.ps1 -Version 3.2.5

# Customize display name (shared or per platform)
```

Key parameters:
- GitHub update has retries (`-GithubRetry/-GithubRetrySec`) to wait for GH Actions to create the initial release record.


Prerequisites: configure secrets in GitHub repository Settings → Secrets
- `GITEE_OWNER`: Your Gitee user/organization name
- `GITEE_REPO`: The repository name on Gitee
- `GITEE_TOKEN`: Your Gitee PAT with permission to create releases
- Optional `GITEE_TARGET_COMMITISH`: If omitted, defaults to `master` (the branch/commit for Gitee to attach the tag when it does not exist)

Steps:
1) GitHub → Actions → select workflow `publish-gitee-manual`
2) Run workflow with inputs:
   - `tag`: e.g., `v3.2.0`
   - `target_commitish`: `master` by default (or a specific branch/commit)
3) Success criteria: the step "Publish release to Gitee (manual)" ends with `Gitee create release HTTP 201/200`.

Script: `tools/dev/quick_push.ps1`
Function: Automatically add/commit/pull --rebase/push all changes to remote.
Usage:
```powershell
Parameters:
- `-Message "message"`: Commit message, required.
- `-PushTags`: Push local tags.

Function: Remote build, sync artifacts, push tag. For official releases.
Usage:
```powershell
.	ools\release\full_release.ps1
```
Parameters: See above "One-click release" section.
Function: Package binaries, docs, source, license into dist directory for distribution.
Usage:
```powershell
.	ools\package_artifacts.ps1 -Version v3.2.1
```

### 4. Remote cross-compilation and smoke test
Script: `tools/remote/remote_build_and_test.sh`
Function: Remote multi-arch cross-compilation, auto sync artifacts, optional smoke test.
Usage:
```bash
tools/remote/remote_build_and_test.sh -H remote_host -u user -k private_key -t arch -r 1 -q "8.8.8.8" -s local_sync_dir
```
Parameters: See above "VS Code Tasks" and script comments.

### 5. Helper scripts
- `tools/dev/prune_artifacts.ps1`: Clean up old artifacts, supports DryRun.
- `tools/dev/tag_release.ps1`: Create and push tag, trigger release.

### Lookup selftests and empty-response fallback verification (3.2.6+)

Purpose: validate the unified fallback strategy for connection failures/empty bodies under a real network, without altering the standard header/tail contract.

How to:
- Run built-in selftests (lookup included):
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -a '--selftest'"
  ```
- Explicitly trigger the empty-response injection path (network required):
  ```powershell
  $env:WHOIS_SELFTEST_INJECT_EMPTY = '1'; & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./out/build_out/whois-x86_64 --selftest"; Remove-Item Env:\WHOIS_SELFTEST_INJECT_EMPTY
  ```

Notes: lookup selftests are network-influenced and advisory; failures are recorded but do not change the selftest exit code. Core selftests (fold/redirect) still determine the overall `--selftest` result.

For more script details or usage examples, refer to this guide or ask the developer assistant.

---

## Developer notes: security log self-test hook (optional, off by default)

Purpose: Quickly validate that `--security-log` rate limiting works without crafting complex network scenarios. The hook only runs when you explicitly enable it and does not alter normal behavior.

Enable (both required):
- Build-time: compile whois with `-DWHOIS_SECLOG_TEST`
- Runtime: set environment variable `WHOIS_SECLOG_TEST=1`

Effect: Early in startup, the program emits a short burst of SECURITY events to stderr to trigger/observe rate limiting; stdout’s header/tail contract remains unchanged. The original `security_logging` setting is restored afterwards.

Examples (local Linux):
```bash
make CFLAGS_EXTRA="-DWHOIS_SECLOG_TEST"
WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help
```

Examples (run on a remote Linux host via SSH):
```bash
ssh ubuntu@203.0.113.10 '
  cd ~/whois && \
  make CFLAGS_EXTRA="-DWHOIS_SECLOG_TEST" && \
  WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help
'
```

Examples (Windows PowerShell, remote self-test, recommended):
```powershell
# 1) Prepare an isolated directory on the remote host
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@remote 'rm -rf ~/whois-wip; mkdir -p ~/whois-wip'

# 2) Upload the local whois project (adjust path, user, and host as needed)
scp -r -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "D:/LZProjects/whois/*" user@remote:~/whois-wip/

# 3) Build with the self-test macro and run the hook
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@remote `
  'cd ~/whois-wip && make clean || true; make CFLAGS_EXTRA=-DWHOIS_SECLOG_TEST && WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help'
```

Notes:
- The executable name is `whois-client` (optionally `whois-client.static` for static builds).
- `--help` is used for quick exit while still exercising the hook.
- Requires OpenSSH on Windows so that `ssh/scp` are available in PowerShell.

Notes:
- `--help` is used to exit quickly while still exercising the hook; any other command line works as well.
- If you omit the build macro or the environment variable, the self-test hook will not run.

---

## Simple remote Makefile build & test (new)

When you just need a quick functional check on a plain Linux box (no cross toolchains), use the bundled `Makefile` remotely.

Prereqs: SSH access, `gcc` installed, and outbound whois (TCP 43) connectivity on the host.

Steps (Windows PowerShell; adjust paths/host/user):
```powershell
# 1) Prepare a clean directory on the remote host
ssh user@host 'rm -rf ~/whois-fast && mkdir -p ~/whois-fast'

# 2) Copy the minimum set (Makefile + src)
scp -r D:/LZProjects/whois/src D:/LZProjects/whois/Makefile user@host:~/whois-fast/

# 3) Build (generates whois-client by default)
ssh user@host 'cd ~/whois-fast && make -j$(nproc)'

# 4) Quick single query check
ssh user@host 'cd ~/whois-fast && ./whois-client 8.8.8.8 | head -n 40'

# 5) Batch check with projection/filtering (via stdin)
ssh user@host "cd ~/whois-fast && printf '8.8.8.8\n1.1.1.1\n' | ./whois-client -B -g 'netname|country' --grep 'GOOGLE|CLOUDFLARE' --grep-line"

# 6) Optional: static link (if toolchain supports it)
ssh user@host 'cd ~/whois-fast && make static'

# 7) Cleanup
ssh user@host 'rm -rf ~/whois-fast'
```

Tips:
- Use `CFLAGS_EXTRA` to inject extra flags, e.g., `make CFLAGS_EXTRA=-DWHOIS_SECLOG_TEST`.
- Batch mode prints the header/tail contract lines to ease manual review.
- This method is for quick validation only and won’t produce multi-arch static artifacts; prefer `tools/remote/remote_build_and_test.sh` for full cross builds.

---

## Developer notes: grep filtering self-test hook (optional)

Purpose: Validate wc_grep’s matching and continuation handling in both block and line modes without relying on live WHOIS responses.

Enable (both required):
- Build-time: compile with `-DWHOIS_GREP_TEST` (e.g., via `CFLAGS_EXTRA` or the remote launcher’s `-E`)
- Runtime: set environment `WHOIS_GREP_TEST=1`

Effect: On startup, a tiny built-in sample is filtered; the program emits lines like:
```
[GREPTEST] block mode: PASS
[GREPTEST] line mode (no-cont): PASS
[GREPTEST] line mode (keep-cont): PASS
```
Failures will include a short dump prefixed with `[GREPTEST-OUT]` for quick diagnostics.

Examples (local Linux):
```bash
make CFLAGS_EXTRA="-DWHOIS_GREP_TEST"
WHOIS_GREP_TEST=1 ./whois-client --help 2>&1 | grep GREPTEST || true
```

Examples (Windows → remote, using the provided launcher):
```powershell
# Append -X 1 to enable both compile-time and runtime (adds -DWHOIS_GREP_TEST; exports WHOIS_GREP_TEST=1)
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8 1.1.1.1' -s '<sync_dir>' -P 1 -a '' -G 0 -E '-O3 -s' -X 1"
```

Heuristics (current behavior):
- Headers must start at column 0; any indented line is treated as a continuation.
- Block mode keeps continuations of matched blocks and suppresses unrelated ones.
- To avoid dropping a meaningful first continuation that looks header-like, the filter allows keeping at most one such indented header-like line globally; subsequent header-like continuations must match the regex to be kept.

Notes:
- Line mode honors `--grep-line` and optionally `--grep-line-keep-cont`; block mode is the default when line mode is off.
- These hooks do not affect normal output when the macro and env var are not both enabled.
