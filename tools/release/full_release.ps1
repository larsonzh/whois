# One-click release pipeline wrapper (PowerShell)
# This simply invokes the bash script with passed arguments.

param(
  [string]$Tag,
  [string]$Queries = '8.8.8.8 1.1.1.1',
  [switch]$NoSmoke,
  [string]$LzisproPath,
  [switch]$DryRun
)

$bash = 'C:\\Program Files\\Git\\bin\\bash.exe'
if (-not (Test-Path $bash)) { throw "Git Bash not found at $bash" }

# Repo root (whois) two levels above this script
$repoRootWin = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

# Convert Windows path (e.g., D:\path) to Git-Bash/MSYS style (/d/path)
$repoRootUnix = $repoRootWin -replace '\\','/'
if ($repoRootUnix -match '^[A-Za-z]:(/.*)$') {
  $drive = $repoRootUnix.Substring(0,1).ToLower()
  $repoRootUnix = '/' + $drive + $Matches[1]
}

$argsList = @()
if ($Tag) { $argsList += @('--tag', $Tag) }
if ($Queries) { $argsList += @('--queries', $Queries) }
if ($NoSmoke) { $argsList += @('--no-smoke') }
if ($LzisproPath) { $argsList += @('--lzispro-path', $LzisproPath) }
if ($DryRun) { $argsList += @('--dry-run') }

$argsJoined = [string]::Join(' ', $argsList)
$cmd = "cd $repoRootUnix; ./tools/release/full_release.sh $argsJoined"

& $bash -lc $cmd
