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

Notes:
- Only creates the Gitee Release page (body from `RELEASE_NOTES.md` + GitHub download links).
- Does not mirror refs to Gitee. If you need to mirror code/tags, add your SSH public key to Gitee and push manually:
  ```powershell
  git push gitee master
  git push gitee --tags
  ```
- For new tags (v3.2.1+), the release workflow includes `target_commitish` automatically; manual backfill is normally unnecessary.
