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
Set-Location $repoRoot

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
  $bashCmd = "cd ${repoRoot.Replace('\\','/')} && $Command"
  & $GitBashPath -lc $bashCmd
  if ($LASTEXITCODE -ne 0) { throw "Git Bash command failed: $Command" }
}

# 2) Update GitHub Release (retry until the release appears)
$ghToken = $env:GH_TOKEN
if (-not $ghToken) { $ghToken = $env:GITHUB_TOKEN }
if (-not $ghToken) { Write-Warning '[one-click] GH_TOKEN/GITHUB_TOKEN not set; skipping GitHub release update.' }
else {
  $attempt = 0
  $ok = $false
  while ($attempt -lt $GithubRetry -and -not $ok) {
    try {
      Invoke-GitBash "GH_TOKEN=$ghToken tools/release/update_release_body.sh $Owner $Repo $tag $bodyRel '$GithubName'"
      $ok = $true
    } catch {
      $attempt++
      if ($attempt -lt $GithubRetry) {
        Write-Warning "[one-click] GitHub release not ready. Retry $attempt/$GithubRetry in $GithubRetrySec s ..."
        Start-Sleep -Seconds $GithubRetrySec
      } else { throw }
    }
  }
}

# 3) Update Gitee Release
$giteeToken = $env:GITEE_TOKEN
if (-not $giteeToken) { Write-Warning '[one-click] GITEE_TOKEN not set; skipping Gitee release update.' }
else {
  Invoke-GitBash "GITEE_TOKEN=$giteeToken ./tools/release/update_gitee_release_body.sh $Owner $Repo $tag ./$bodyRel '$GiteeName'"
}

if ($skipTagEffective) {
  Write-Host "[one-click] Done. (Tag step skipped) Tag (computed): $tag; GitHub/Gitee release bodies updated where tokens were provided." -ForegroundColor Green
} else {
  Write-Host "[one-click] Done. Tag: $tag; GitHub/Gitee release bodies updated where tokens were provided." -ForegroundColor Green
}
