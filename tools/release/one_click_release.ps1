# One-click release orchestrator (PowerShell)
#
# Purpose:
# - Create and push annotated tag v<Version>
# - Update GitHub Release body/name from docs/release_bodies/v<Version>.md
# - Update Gitee Release body/name from the same file
#
# Requirements:
# - Git (for tagging)
# - Git Bash (for running the shipped .sh helpers)
# - curl & jq available in Git Bash environment
# - Environment tokens:
#   * GH_TOKEN or GITHUB_TOKEN
#   * GITEE_TOKEN
#
# Usage examples (PowerShell):
#   .\tools\release\one_click_release.ps1 -Version 3.2.4
#   .\tools\release\one_click_release.ps1 -Version 3.2.4 -GithubName "whois v3.2.4" -GiteeName "whois v3.2.4"
#   .\tools\release\one_click_release.ps1 -Version 3.2.4 -SkipTag
#
# Version scheme note (>=3.2.6):
#   Default builds use simplified versioning (no automatic '-dirty' suffix) to reduce friction.
#   For strict audit-style builds that append '-dirty' when tracked changes exist, run the
#   remote build via the VS Code task "Remote: Build (Strict Version)" or set environment:
#     $env:WHOIS_STRICT_VERSION = 1
#   before invoking the remote build script.
#
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Owner = 'larsonzh',
  [string]$Repo = 'whois',
  [string]$GithubName,
  [string]$GiteeName,
  [switch]$SkipTag,              # legacy switch (still honored)
  [string]$SkipTagIf = 'false',  # new string flag ('true'/'false') to allow VS Code task injection
  [switch]$PushGiteeTag,
  [string]$GitBashPath = 'C:\\Program Files\\Git\\bin\\bash.exe',
  [int]$GithubRetry = 6,
  [int]$GithubRetrySec = 10
)

$ErrorActionPreference = 'Stop'

function Assert-File {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
}

if (-not $GithubName) { $GithubName = "whois v$Version" }
if (-not $GiteeName)  { $GiteeName  = "whois v$Version" }

# Determine effective skip-tag decision (supports old -SkipTag switch and new -SkipTagIf string)
$skipTagEffective = $false
if ($SkipTag.IsPresent) { $skipTagEffective = $true }
elseif ($SkipTagIf -and $SkipTagIf.ToLower() -eq 'true') { $skipTagEffective = $true }

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw 'git not found in PATH'
}
if (-not (Test-Path -LiteralPath $GitBashPath)) {
  throw "Git Bash not found: $GitBashPath"
}

# Resolve repo root (two levels up from this script)
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Write-Host "[one-click][debug] PSScriptRoot=$PSScriptRoot repoRoot=$repoRoot"
Set-Location $repoRoot

# Tip: Versioning policy (since v3.2.6)
Write-Host "[one-click] 提示：默认构建使用简化版号（不追加 -dirty）。如需严格模式，请在远程构建前使用 VS Code 任务 \"Remote: Build (Strict Version)\" 或设置 WHOIS_STRICT_VERSION=1。" -ForegroundColor Yellow

# Validate version/tag and body file
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid version: $Version (expected X.Y.Z)" }
$tag = "v$Version"
$bodyRel = "docs/release_bodies/v$Version.md"
Assert-File $bodyRel

# 1) Create and push tag (if not skipped)
if (-not $skipTagEffective) {
  try {
    & "$repoRoot\tools\dev\tag_release.ps1" -Tag $tag -Message "whois $tag" -PushGitee:$PushGiteeTag
  } catch {
    if ($_.Exception.Message -match 'Tag already exists') {
      Write-Warning "[one-click] Tag $tag already exists. Continuing."
    } else { throw }
  }
}

# Helper: run a command in Git Bash with repo root as CWD
function Invoke-GitBash {
  param([string]$Command)
  $cdPath = ($repoRoot -replace '\\','/')
  # Build the bash command by joining segments to avoid parser confusion with inline special chars
  $segments = @("cd '$cdPath'", 'pwd', 'ls -la', $Command)
  $bashCmd = [string]::Join('; ', $segments)
  Write-Host ('[one-click][debug] bash -lc: ' + $bashCmd)
  & $GitBashPath -lc $bashCmd
  if ($LASTEXITCODE -ne 0) { throw "Git Bash command failed: $Command" }
}

# 2) Update GitHub Release (retry until the release appears)
$ghToken = $env:GH_TOKEN
if (-not $ghToken) { $ghToken = $env:GITHUB_TOKEN }
if (-not $ghToken) { Write-Warning "[one-click] GH_TOKEN/GITHUB_TOKEN not set; skipping GitHub release update." }
else {
  $attempt = 0
  $ok = $false
  while ($attempt -lt $GithubRetry -and -not $ok) {
    try {
      $ghCmd = ("GH_TOKEN='{0}' ./tools/release/update_release_body.sh {1} {2} {3} {4} '{5}'" -f $ghToken, $Owner, $Repo, $tag, $bodyRel, $GithubName)
      Invoke-GitBash $ghCmd
      $ok = $true
    } catch {
      $attempt++
      if ($attempt -lt $GithubRetry) {
        Write-Warning "one-click warn: GitHub release not ready. Retry $attempt/$GithubRetry in $GithubRetrySec s ..."
        Start-Sleep -Seconds $GithubRetrySec
      } else { throw }
    }
  }
}

# 3) Update Gitee Release
$giteeToken = $env:GITEE_TOKEN
if (-not $giteeToken) { Write-Warning 'one-click warn: GITEE_TOKEN not set; skipping Gitee release update.' }
else {
  $geCmd = ("GITEE_TOKEN='{0}' ./tools/release/update_gitee_release_body.sh {1} {2} {3} ./{4} '{5}'" -f $giteeToken, $Owner, $Repo, $tag, $bodyRel, $GiteeName)
  Invoke-GitBash $geCmd
}

if ($skipTagEffective) {
  Write-Host ('[one-click] Done. (Tag step skipped) Tag (computed): ' + $tag + '; GitHub/Gitee release bodies updated where tokens were provided.') -ForegroundColor Green
} else {
  Write-Host ('[one-click] Done. Tag: ' + $tag + '; GitHub/Gitee release bodies updated where tokens were provided.') -ForegroundColor Green
}
