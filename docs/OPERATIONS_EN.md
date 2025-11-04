# whois Operations and Release Guide (English)

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

## Troubleshooting

### ARIN port 43 unreachable (Connection refused/timeout)

Symptom: queries for `8.8.8.8` (authoritative RIR = ARIN) fail while others work; `ping` succeeds but `whois` fails. This usually means TCP/43 egress is blocked or ARIN rate-limits/denies your source IP.

Quick checks (on the target host):

```bash
# Basic connectivity (several ARIN A/AAAA)
nc -vz whois.arin.net 43 || true
nc -vz 199.71.0.46 43 || true
nc -vz 199.5.26.46 43 || true

# Compare with other RIRs (rule out global 43 block)
nc -vz whois.ripe.net 43 || true
nc -vz whois.apnic.net 43 || true

# System whois (if installed)
which whois && whois 8.8.8.8 | head -n 20
```

Local/network policy checks:

```bash
sudo ufw status
sudo iptables -S; sudo ip6tables -S
sudo nft list ruleset
```

If only ARIN:43 fails:
- Review host/cloud security group/gateway ACL for TCP/43 or specific ARIN ranges (e.g., 199.71.0.0/…, 199.5.26.0/…, 199.212.0.0/…).
- ARIN may rate-limit/blacklist your source IP (historical high volume); switch egress IP (jump host/VPN/proxy) or wait.
- IPv6 “Network is unreachable” means IPv6 routing isn’t configured; can be ignored or configured separately.

Workarounds:
- Use `-Q` to get IANA non-authoritative result only: `./whois-client -Q 8.8.8.8`
- Optional RDAP fallback (HTTPS 443): see below.

### RDAP fallback (optional)

To bypass environments that block port 43, you can enable RDAP fallback (depends on system `curl`, off by default).

```bash
# Only triggered when the primary WHOIS query fails; enable with --rdap-fallback=allow-shell; requires system curl
./whois-client --rdap-fallback=allow-shell 8.8.8.8
```

Notes:
- RDAP uses the IANA bootstrap endpoint `https://rdap.iana.org/ip/<IP>`, automatically routing to the proper RIR.
- The program never calls external tools on normal paths; it only tries system `curl` when you pass `--rdap-fallback=allow-shell`.
- If `curl` is not installed, the program will skip RDAP gracefully and print a hint.
- The output is the raw RDAP content (JSON/plain), intended for outage workaround and diagnosis.

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
