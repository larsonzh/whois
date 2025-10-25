param(
    [Parameter(Mandatory=$true)] [string]$Path,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Path)) { throw "Path not found: $Path" }

Write-Host "[PRUNE] Target: $Path" -ForegroundColor Cyan

# Remove subdirectories entirely
$dirs = Get-ChildItem -Path $Path -Directory -Force -ErrorAction SilentlyContinue
foreach ($d in $dirs) {
    if ($WhatIf) {
        Write-Host "[WHATIF] Remove dir: $($d.FullName)"
    } else {
        Remove-Item -Recurse -Force $d.FullName
    }
}

# Remove files that are NOT whois-*
$files = Get-ChildItem -Path $Path -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'whois-*' }
foreach ($f in $files) {
    if ($WhatIf) {
        Write-Host "[WHATIF] Remove file: $($f.FullName)"
    } else {
        Remove-Item -Force $f.FullName
    }
}

Write-Host "[PRUNE] Done" -ForegroundColor Green
