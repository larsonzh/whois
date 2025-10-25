# One-click release pipeline wrapper (PowerShell)
# This simply invokes the bash script with passed arguments.

param(
  [string]$Tag,
  # Default to a single query to avoid quoting issues; multiple can be passed via -Queries "8.8.8.8 1.1.1.1"
  [string]$Queries = '8.8.8.8',
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
if ($Tag) {
  $t = $Tag; if ($t -match ' ') { $t = "'$t'" }
  $argsList += @('--tag', $t)
}
if ($Queries) {
  $q = $Queries; if ($q -match ' ') { $q = "'$q'" }
  $argsList += @('--queries', $q)
}
if ($NoSmoke) { $argsList += @('--no-smoke') }
if ($LzisproPath) {
  $lp = $LzisproPath; if ($lp -match ' ') { $lp = "'$lp'" }
  $argsList += @('--lzispro-path', $lp)
}
if ($DryRun) { $argsList += @('--dry-run') }

$argsJoined = [string]::Join(' ', $argsList)
$cmd = "cd $repoRootUnix; ./tools/release/full_release.sh $argsJoined"

& $bash -lc $cmd
