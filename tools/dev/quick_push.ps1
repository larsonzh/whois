# Quick git add/commit/pull --rebase/push helper (PowerShell)
# Usage examples:
#   .\tools\dev\quick_push.ps1 -Message "fix: something"           # push to origin master
#   .\tools\dev\quick_push.ps1 -Message "docs: update" -PushGitee   # also push gitee
#   .\tools\dev\quick_push.ps1 -Message "chore" -Branch develop     # push to origin develop
#   .\tools\dev\quick_push.ps1 -Message "release" -PushTags         # also push tags

param(
  [string]$Message = "chore: quick push",
  [string]$Branch = "master",
  [switch]$PushGitee,
  [switch]$PushTags,
  [switch]$AllowEmpty
)

$ErrorActionPreference = 'Stop'

# Resolve repo root (two levels up from tools/dev)
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Write-Host "[quick-push] repo: $repoRoot"
Write-Host "[quick-push] branch: $Branch; pushGitee=$PushGitee; pushTags=$PushTags"

# Ensure git exists
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw "git not found in PATH"
}

# Helper to run git in repo
function GitR() { param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
  & git -C $repoRoot @Args
}

# Ensure git uses Windows OpenSSH (avoids msys ssh with localized HOME issues)
GitR 'config' 'core.sshCommand' 'C:/Windows/System32/OpenSSH/ssh.exe'

# Stage changes
GitR 'add' '-A'

# Detect if there is anything to commit
$porcelain = GitR 'status' '--porcelain'
if ([string]::IsNullOrWhiteSpace($porcelain)) {
  if (-not $AllowEmpty) {
    Write-Host "[quick-push] No changes to commit. Use -AllowEmpty to force an empty commit." -ForegroundColor Yellow
  } else {
    GitR 'commit' '--allow-empty' '-m' $Message
  }
} else {
  GitR 'commit' '-m' $Message
}

# Rebase pull and push to origin
GitR 'pull' '--rebase' 'origin' $Branch
GitR 'push' 'origin' $Branch

# Optional: push tags
if ($PushTags) {
  GitR 'push' 'origin' '--tags'
}

# Optional: push to gitee
if ($PushGitee) {
  try {
    $gurl = GitR 'remote' 'get-url' 'gitee' 2>$null
  } catch { $gurl = $null }
  if (-not $gurl) {
    Write-Host "[quick-push] remote 'gitee' not found. Add it with:`n    git remote add gitee git@gitee.com:<owner>/<repo>.git" -ForegroundColor Yellow
  } else {
    GitR 'push' 'gitee' $Branch
    if ($PushTags) { GitR 'push' 'gitee' '--tags' }
  }
}

Write-Host "[quick-push] Done." -ForegroundColor Green
