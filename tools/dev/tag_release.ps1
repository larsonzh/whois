# Create and push an annotated tag (PowerShell)
# Usage:
#   .\tools\dev\tag_release.ps1 -Tag v3.1.10 [-Message "Release v3.1.10"] [-PushGitee]

param(
  [Parameter(Mandatory=$true)][string]$Tag,
  [string]$Message,
  [switch]$PushGitee
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw "git not found in PATH"
}

# Resolve repo root
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

# Validate tag format vX.Y.Z
if ($Tag -notmatch '^v\d+\.\d+\.\d+$') {
  throw "Invalid tag format '$Tag'. Expected vX.Y.Z (e.g., v3.1.10)"
}

if (-not $Message) { $Message = "Release $Tag" }

function GitR() { param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
  & git -C $repoRoot @Args
}

# Check existing tag
$exists = GitR rev-parse -q --verify $Tag 2>$null; if ($LASTEXITCODE -eq 0) {
  throw "Tag already exists: $Tag"
}

Write-Host "[tag-release] repo: $repoRoot"
Write-Host "[tag-release] creating tag $Tag"

GitR tag -a $Tag -m $Message
GitR push origin $Tag

if ($PushGitee) {
  try { $gurl = GitR remote get-url gitee 2>$null } catch { $gurl = $null }
  if ($gurl) {
    GitR push gitee $Tag
  } else {
    Write-Host "[tag-release] remote 'gitee' not found. Add it with:`n  git remote add gitee git@gitee.com:<owner>/<repo>.git" -ForegroundColor Yellow
  }
}

Write-Host "[tag-release] Done. A GitHub Action will publish the release for $Tag." -ForegroundColor Green
