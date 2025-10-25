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

$scriptPath = Join-Path $PSScriptRoot 'full_release.sh'
if (-not (Test-Path $scriptPath)) { throw "Missing script: $scriptPath" }

$argsList = @()
if ($Tag) { $argsList += @('--tag', $Tag) }
if ($Queries) { $argsList += @('--queries', $Queries) }
if ($NoSmoke) { $argsList += @('--no-smoke') }
if ($LzisproPath) { $argsList += @('--lzispro-path', $LzisproPath) }
if ($DryRun) { $argsList += @('--dry-run') }

& $bash -lc "'${scriptPath.Replace('\\','/')}' $([string]::Join(' ', $argsList))"
