# One-Click Release Flow (whois)

Also available in Chinese: `RELEASE_FLOW_CN.md`.

This document describes how to complete a full release locally in one go:

- Cross-compile 7 static binaries for multiple architectures + online smoke tests
- Sync static artifacts to lzispro and automatically commit/push
- (Optional) commit the updated `RELEASE_NOTES.md`
- Create a tag to trigger GitHub Release (CI will automatically attach `whois-x86_64-gnu` + the 7 static binaries)

> CI and remote SSH notes:
> - GitHub Actions workflows that involve remote SSH (cross-machine cross-compilation / artifact collection) are switched to manual trigger (workflow_dispatch) to avoid failures when hosted runners cannot reach private hosts.
> - Recommendation: run `tools/remote/remote_build_and_test.sh` from your local machine to complete remote build and smoke tests. If you need CI, prefer a self-hosted runner.
> - Troubleshooting: set `WHOIS_DEBUG_SSH=1` to enable `ssh -vvv` verbose debug logs.

## Quick Usage (PowerShell)

Run in the whois repo root:

```powershell
# Auto-increment tag (based on current max vX.Y.Z), smoke test enabled by default, default query 8.8.8.8
# Automatically detects a sibling lzispro directory, or specify via --lzispro-path
./tools/release/full_release.ps1

# Specify the tag and query targets
./tools/release/full_release.ps1 -Tag v3.1.9 -Queries '8.8.8.8 1.1.1.1'

# Disable smoke tests
./tools/release/full_release.ps1 -NoSmoke

# Specify lzispro path (e.g., D:\LZProjects\lzispro)
./tools/release/full_release.ps1 -LzisproPath 'D:\LZProjects\lzispro'
```

Equivalent Git Bash (usable on CI hosts or WSL):

```bash
./tools/release/full_release.sh --tag v3.1.9 --queries '8.8.8.8 1.1.1.1'
```

## Versioning Rules
- If `--tag/-Tag` is not provided, the script finds the largest existing `vX.Y.Z` tag in the whois repo and increments Z by 1 as the next version.
- If that tag already exists, the script aborts to avoid a duplicate release.
- Version marking strategy (since 3.2.6): by default builds no longer append the `-dirty` suffix to reduce unnecessary tag/commit operations. If you need strict detection and want `-dirty` added when tracked changes are present (for audit or formal release verification), set `WHOIS_STRICT_VERSION=1` before invoking the remote build script. For example:
  ```powershell
  $env:WHOIS_STRICT_VERSION = 1
  & 'C:\Program Files\Git\bin\bash.exe' -lc "tools/remote/remote_build_and_test.sh -r 1"
  ```
  Or use the VS Code Task “Remote: Build (Strict Version)”.

## Directories and Sync
- The 7 static binaries are synced to: `<lzispro>/release/lzispro/whois/` by default.
- After tagging, the GitHub Actions release workflow reads that directory (or `<lzispro>/release/lzispro/whois/whois`, both supported) from the lzispro master branch to collect assets and generate a consolidated `SHA256SUMS.txt`.

## Execution Details (full_release.sh)
1. Call `tools/remote/remote_build_and_test.sh`:
   - Parameters: `-r 1` (can be disabled), `-q '<queries>'`, `-s '<lzispro>/release/lzispro/whois' -P 1` (clean non whois-* files in the target first)
   - By default Step 1 output is saved to `out/release_flow/<timestamp>/step1_remote.log`. If any warnings/errors are detected (`warning:`, `[WARN]`, `[ERROR]`), the script aborts immediately. You can disable this behavior with `--strict-warn 0`.
2. In the lzispro repo run `git add release/lzispro/whois/whois-* && commit && push` (skip if no changes)
3. In the whois repo run `git add RELEASE_NOTES.md && commit && push` (skip if no changes)
4. In the whois repo create and push the tag `vX.Y.Z` to trigger the Release

## FAQ
- Tag missing/already exists: when tag is not provided, we auto-increment; if the target tag already exists, the script aborts to avoid duplication.
- lzispro not found: the script auto-detects a sibling `lzispro` directory next to whois. You can also specify it explicitly with `--lzispro-path`.
- Missing assets: ensure Step 2 has been committed and pushed to GitHub, and check the workflow logs to confirm the 7 static binaries were copied from lzispro.

---

## Stable Release Best Practices

- Core principle: do it once. Commit and push all code and docs first, then use the VS Code One-Click Release task to complete “tag + remote build + smoke + sync + commit/push + trigger workflow + update GitHub/Gitee release body” in one shot. Avoid splitting into manual multi-step operations.
- Pre-checklist:
  - Clean workspace: no uncommitted changes (including `release/lzispro/whois/`, `docs/release_bodies/vX.Y.Z.md`).
  - Doc consistency: `README.md`, `RELEASE_NOTES.md`, and `docs/release_bodies/vX.Y.Z.md` are aligned; bilingual order is consistent (Chinese first, English after; or in-line Chinese before English).
  - Direct download links: use absolute GitHub links to assets in the release body and include `SHA256SUMS.txt`.
  - Version availability: the target version is not taken; to reuse, you must delete the old online Release and tag first.
  - Credentials ready: GitHub `GITHUB_TOKEN/GH_TOKEN`, Gitee `GITEE_TOKEN` (if mirrored).
- One-Click Release suggestions:
  - Use `skipTag=false`, `buildSync=true`; ensure `rbHost/rbUser/rbKey` are correct; set `rbSmoke=1`, and provide 1–2 `rbQueries`; keep `rbSmokeArgs` empty or minimal; `rbSyncDir` supports multiple directories separated by semicolons.
  - Strict versioning: use the task’s “strict build” or set `WHOIS_STRICT_VERSION=1` to ensure a clean `vX.Y.Z` in artifacts.
- Common pitfalls:
  - Manually pushing the tag or running remote build first and then calling the task often leads to “tag out of sync with body/assets”.
  - Filling placeholders like `rbSmokeArgs` in the task form (even if valid) can change smoke behavior—leave empty if not needed.
  - Repeatedly deleting/repushing the same tag can leave the Release in draft or asset-less states.
- Post-release verification:
  - Actions run: the release workflow succeeds, and 7 binaries + `SHA256SUMS.txt` appear as release assets.
  - Artifact version: binaries in your local sync directory print a clean `vX.Y.Z` for `-v`.
  - Body: GitHub/Gitee release titles and contents match the current version.
- Fix strategies:
  - Body-only mistakes: run One-Click Release with `skipTag=true`, `buildSync=false` to refresh the body only.
  - Missing assets: delete local + remote tag → ensure artifacts are committed and pushed → run a full One-Click (do not skip tag).
  - Version has `-dirty`: the build saw a dirty workspace—clean it up and re-run the full flow.

### Network-Window Revalidation (2026-02-21)

- Applicable scenario: gates show stable external denial/rate-limit patterns (for example RIPE returning `%ERROR:201: access denied` for the current IPv4 egress), likely unrelated to code behavior.
- Principle: keep authority semantics and output contracts unchanged; isolate environment noise only at test-parameter level.
- Suggested parameter: add `-RirIpPref arin=ipv6,ripe=ipv6` to matrix/revalidation runs (or switch only affected RIRs to IPv6).
- Evidence requirement: record both default-parameter results and revalidation results (`authMismatchFiles`, `errorFiles`, and log paths) in release notes or RFC logs.
- Exit condition: once egress policy recovers, rerun gates with default parameters to ensure there is no environment-specific dependency.
