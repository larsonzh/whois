# whois Operations & Release Guide

Chinese version: `docs/OPERATIONS_CN.md`

This guide summarizes common day-to-day tasks: commit/push, remote cross-compilation + smoke tests, and publishing releases to GitHub and Gitee.

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

New task:
- One-Click Release (invokes `tools/release/one_click_release.ps1` to update GitHub/Gitee Release; optionally skip creating/pushing a tag)

Prompts when running One-Click Release:
- releaseVersion: plain version (no leading `v`), e.g. `3.2.3`. Used to read `docs/release_bodies/vX.Y.Z.md` and compute tag name.
- releaseName: display name for both GitHub and Gitee, default `whois v<version>`.
- skipTag: whether to skip creating/pushing the tag (`true`/`false`).

Underlying command (PowerShell):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/release/one_click_release.ps1 `
  -Version <releaseVersion> -GithubName <releaseName> -GiteeName <releaseName> -SkipTagIf <skipTag>
```

Notes:
- If `skipTag=true`, the script only updates Release body/name for an existing tag; it won’t create/push a tag.
- Tokens: GitHub requires `GH_TOKEN` or `GITHUB_TOKEN`; Gitee requires `GITEE_TOKEN`. Missing tokens are skipped with a warning.
- Prefer exercising this in the next version’s cycle to avoid churning current stable content.

---

## Artifacts housekeeping

- Since v3.2.0, the directory `out/artifacts/` is ignored by Git and no longer tracked.
- To clean up old local artifacts, use the PowerShell helper `tools/dev/prune_artifacts.ps1` (supports `-DryRun`).

---

## Tag and publish (optional)

Script: `tools/dev/tag_release.ps1`

Example:
```powershell
.\tools\dev\tag_release.ps1 -Tag v3.2.0 -Message "Release v3.2.0"
```

Pushing a tag triggers the GitHub Actions release workflow, which creates a GitHub Release and uploads artifacts. If the Gitee secrets are configured, it will also create a corresponding Gitee Release page with download links to GitHub.

### New script: one_click_release.ps1

Path: `tools/release/one_click_release.ps1`

Purpose: one-click update of GitHub/Gitee Release body and display name; can optionally skip the tag creation/push (same behavior as the VS Code task).

Examples:
```powershell
# Create/push tag + update both releases
./tools/release/one_click_release.ps1 -Version 3.2.3

# Only update release body/name for an existing tag (skip tagging)
./tools/release/one_click_release.ps1 -Version 3.2.3 -SkipTagIf true

# Customize display name (shared or per platform)
./tools/release/one_click_release.ps1 -Version 3.2.3 -GithubName "whois v3.2.3" -GiteeName "whois v3.2.3"
```

Key parameters:
- `-Version X.Y.Z` required; reads `docs/release_bodies/vX.Y.Z.md` as the body source.
- `-SkipTag` or `-SkipTagIf 'true'` to skip tagging; either works.
- `-PushGiteeTag` optional to mirror the tag to `gitee` remote.
- GitHub update has retries (`-GithubRetry/-GithubRetrySec`) to wait for GH Actions to create the initial release record.

---

## Manual backfill to Gitee Release (publish-gitee-manual)

Use this when an older tag failed to create a Gitee Release (e.g., HTTP 400 target_commitish is missing), or you simply want to backfill an existing GitHub Release to Gitee. This workflow only creates a Gitee Release page and appends download links to GitHub assets; it does NOT push code/tags to Gitee.

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


---

## Script Quick Reference

### 1. One-click commit and push (recommended for daily sync)
Script: `tools/dev/quick_push.ps1`
Function: Automatically add/commit/pull --rebase/push all changes to remote.
Usage:
```powershell
.	ools\dev\quick_push.ps1 -Message "Fix bug or update notes"
```
Parameters:
- `-Message "message"`: Commit message, required.
- `-PushGitee`: Also push to gitee remote (must add gitee remote first).
- `-Branch branchName`: Specify branch.
- `-PushTags`: Push local tags.

### 2. One-click release new version
Script: `tools/release/full_release.ps1`
Function: Remote build, sync artifacts, push tag. For official releases.
Usage:
```powershell
.	ools\release\full_release.ps1
```
Parameters: See above "One-click release" section.

### 3. Artifact packaging and archiving
Script: `tools/package_artifacts.ps1`
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
