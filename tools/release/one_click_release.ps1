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
  [ValidateSet('true','false')][string]$SkipTagIf = 'false',  # enforce explicit string boolean
  [switch]$PushGiteeTag,
  [string]$GitBashPath = 'C:\\Program Files\\Git\\bin\\bash.exe',
  [int]$GithubRetry = 6,
  [int]$GithubRetrySec = 10,
  # Optional: remote build + smoke + sync statics, then commit & push (default ON)
  [ValidateSet('true','false')][string]$BuildAndSyncIf = 'true',
  [string]$RbHost,
  [string]$RbUser = 'ubuntu',
  [string]$RbKey,
  [string]$RbSmoke = '1',
  [string]$RbQueries = '8.8.8.8',
  # Accept explicit empty sentinel '--' from VS Code task to avoid missing argument parse error
  [AllowEmptyString()][string]$RbSmokeArgs = '',
  [string]$RbGolden = '1',
  [string]$RbCflagsExtra = '-O3 -s',
  # Support multiple sync dirs separated by ';' or ','
  [string]$RbSyncDir
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
Write-Host ("one-click debug: PSScriptRoot={0} repoRoot={1}" -f $PSScriptRoot, $repoRoot)
Set-Location $repoRoot

# Tip: Versioning policy (since v3.2.6)
Write-Host 'one-click tip: simplified versioning active (no -dirty). For strict mode use VS Code task: Remote: Build (Strict Version) or set WHOIS_STRICT_VERSION=1.' -ForegroundColor Yellow

# Validate version/tag and body file
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid version: $Version (expected X.Y.Z)" }
$tag = "v$Version"
$bodyRel = "docs/release_bodies/v$Version.md"
Assert-File $bodyRel

# Compute repoRoot in Git-Bash (/d/...) form and default sync path
$repoRootUnix = ($repoRoot -replace '\\','/')
if ($repoRootUnix -match '^[A-Za-z]:(/.*)$') {
  $drive = $repoRootUnix.Substring(0,1).ToLower()
  $repoRootUnix = '/' + $drive + $Matches[1]
}
if (-not $RbSyncDir -or $RbSyncDir.Trim() -eq '') {
  $RbSyncDir = "$repoRootUnix/release/lzispro/whois"
}

# Normalize smoke args: treat sentinels as intentional empty
if ($RbSmokeArgs -in @('--','NONE','__EMPTY__')) { $RbSmokeArgs = '' }

# Defensive guard: detect swallowed flag being passed as RbSmokeArgs value (common when value omitted)
if ($PSBoundParameters.ContainsKey('RbSmokeArgs')) {
  $trimVal = $RbSmokeArgs.Trim()
  if ($trimVal -match '^-{1,2}[A-Za-z]') {
    throw 'Invocation parsing error: -RbSmokeArgs value missing; "' + $trimVal + '" looks like a flag. Please set -RbSmokeArgs "--" or a real value.'
  }
}

# Split sync dirs (first used for remote script -s)
$rbSyncDirList = $RbSyncDir -split '[;,]' | Where-Object { $_ -and $_.Trim() -ne '' }
if ($rbSyncDirList.Count -eq 0) { $rbSyncDirList = @("$repoRootUnix/release/lzispro/whois") }
$primarySyncDir = $rbSyncDirList[0]
$extraSyncDirs  = @()
if ($rbSyncDirList.Count -gt 1) { $extraSyncDirs = $rbSyncDirList[1..($rbSyncDirList.Count-1)] }

# 1) Create and push tag (if not skipped)
if (-not $skipTagEffective) {
  try {
    & "$repoRoot\tools\dev\tag_release.ps1" -Tag $tag -Message "whois $tag" -PushGitee:$PushGiteeTag
  } catch {
    if ($_.Exception.Message -match 'Tag already exists') {
      Write-Warning ("one-click warn: tag {0} already exists. continuing." -f $tag)
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
  Write-Host ('one-click debug: bash -lc: ' + $bashCmd)
  & $GitBashPath -lc $bashCmd
  if ($LASTEXITCODE -ne 0) { throw "Git Bash command failed: $Command" }
}

# 0) Optional remote build + smoke + sync statics, then commit & push (default ON)
$doBuild = ($BuildAndSyncIf -and $BuildAndSyncIf.ToLower() -eq 'true')
if ($doBuild) {
  if (-not $RbHost) {
    Write-Warning 'one-click warn: RbHost not set; skipping build/sync.'
  } else {
    $argSmoke = ''
    if ($RbSmokeArgs -and $RbSmokeArgs.Trim() -ne '') { $argSmoke = "-a '$RbSmokeArgs'" }
    $rbCmd = "tools/remote/remote_build_and_test.sh -H $RbHost -u $RbUser -k '$RbKey' -r $RbSmoke -q '$RbQueries' -s '$primarySyncDir' -P 1 $argSmoke -G $RbGolden -E '$RbCflagsExtra'"
    Invoke-GitBash $rbCmd

    # Stage and commit synced statics if changed
    $staticsPath = Join-Path $repoRoot 'release\lzispro\whois'
    if (Test-Path $staticsPath) {
      git add "$staticsPath\whois-*" | Out-Null
      $changes = git status --porcelain
      if ($changes) {
        git commit -m ("release: update whois statics for v{0}" -f $Version) | Out-Null
        git push origin HEAD | Out-Null
        Write-Host 'one-click info: statics committed and pushed.' -ForegroundColor Green
      } else {
        Write-Host 'one-click info: no statics changes to commit.' -ForegroundColor Yellow
      }
    } else {
      Write-Warning "one-click warn: statics path not found: $staticsPath"
    }

    # Replicate statics to extra sync dirs if requested
    if ($extraSyncDirs.Count -gt 0) {
      Write-Host ("one-click info: replicating statics to {0} extra sync dir(s)." -f $extraSyncDirs.Count)
      foreach ($unixDir in $extraSyncDirs) {
        # Convert unix /d/... path to Windows drive style if necessary
        $winDir = $unixDir
        if ($unixDir -match '^/([a-zA-Z])/(.*)$') {
          $drive = $Matches[1].ToUpper()
          $rest  = $Matches[2] -replace '/', '\'
          $winDir = "${drive}:\$rest"
        }
        # Skip if destination resolves to source statics path (avoid self-copy errors)
        try {
          $resolvedSrc = Resolve-Path -LiteralPath $staticsPath -ErrorAction Stop
          if (Test-Path -LiteralPath $winDir) {
            $resolvedDest = Resolve-Path -LiteralPath $winDir -ErrorAction SilentlyContinue
            if ($resolvedDest -and $resolvedDest.ProviderPath -eq $resolvedSrc.ProviderPath) {
              Write-Host ("one-click info: skip replication for identical path: {0}" -f $winDir) -ForegroundColor Yellow
              continue
            }
          }
        } catch { }
        if (-not (Test-Path -LiteralPath $winDir)) { New-Item -ItemType Directory -Path $winDir | Out-Null }
        $srcPattern = Join-Path $staticsPath 'whois-*'
        Copy-Item $srcPattern -Destination $winDir -Force -ErrorAction Stop
        Write-Host ("one-click info: replicated statics to {0}" -f $winDir)
      }
    }
  }
}

# 2) Update GitHub Release (retry until the release appears)
$ghToken = $env:GH_TOKEN
if (-not $ghToken) { $ghToken = $env:GITHUB_TOKEN }
if (-not $ghToken) { Write-Warning 'one-click warn: GH_TOKEN/GITHUB_TOKEN not set; skipping GitHub release update.' }
else {
  $attempt = 0
  $ok = $false
  while ($attempt -lt $GithubRetry -and -not $ok) {
    try {
      $ghFmt = @'
GH_TOKEN='{0}' ./tools/release/update_release_body.sh {1} {2} {3} {4} '{5}'
'@
      $ghCmd = ($ghFmt -f $ghToken, $Owner, $Repo, $tag, $bodyRel, $GithubName)
      Invoke-GitBash $ghCmd
      $ok = $true
    } catch {
      $attempt++
      if ($attempt -lt $GithubRetry) {
  $warnMsg = ('one-click warn: github release not ready. retry {0}/{1} in {2}s ...' -f $attempt, $GithubRetry, $GithubRetrySec)
  Write-Warning $warnMsg
        Start-Sleep -Seconds $GithubRetrySec
      } else { throw }
    }
  }
}

# 3) Update Gitee Release
$giteeToken = $env:GITEE_TOKEN
if (-not $giteeToken) { Write-Warning 'one-click warn: GITEE_TOKEN not set; skipping Gitee release update.' }
else {
  $geFmt = @'
GITEE_TOKEN='{0}' ./tools/release/update_gitee_release_body.sh {1} {2} {3} ./{4} '{5}'
'@
  $geCmd = ($geFmt -f $giteeToken, $Owner, $Repo, $tag, $bodyRel, $GiteeName)
  Invoke-GitBash $geCmd
}

if ($skipTagEffective) {
  Write-Host ('one-click done: tag step skipped; tag=' + $tag) -ForegroundColor Green
} else {
  Write-Host ('one-click done: tag=' + $tag) -ForegroundColor Green
}
