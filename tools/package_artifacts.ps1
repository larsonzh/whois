param(
    [Parameter(Mandatory=$true)] [string]$Version,
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist')
)

$ErrorActionPreference = 'Stop'

function New-CleanDirectory($Path) {
    if (Test-Path $Path) { Remove-Item -Recurse -Force $Path }
    New-Item -ItemType Directory -Path $Path | Out-Null
}

# Layout: dist/whois-<version>/{bin/<arch>,docs,src,licenses}
$packageName = "whois-$Version"
$packageDir = Join-Path $OutputRoot $packageName
$binDir     = Join-Path $packageDir 'bin'
$docsDir    = Join-Path $packageDir 'docs'
$srcDir     = Join-Path $packageDir 'src'
$licDir     = Join-Path $packageDir 'licenses'

Write-Host "[INFO] Packaging whois artifacts: version=$Version" -ForegroundColor Cyan
Write-Host "[INFO] RepoRoot: $RepoRoot" -ForegroundColor Cyan
Write-Host "[INFO] Output: $packageDir" -ForegroundColor Cyan

New-CleanDirectory $packageDir
New-Item -ItemType Directory -Path $binDir,$docsDir,$srcDir,$licDir | Out-Null

# 1) Collect binaries from repo root
#    Support both whois-* (e.g., whois-aarch64) and whois-client
$binCandidates = @()
$binCandidates += Get-ChildItem -File (Join-Path $RepoRoot 'whois-*') -ErrorAction SilentlyContinue
$wc = Get-ChildItem -File (Join-Path $RepoRoot 'whois-client') -ErrorAction SilentlyContinue
if ($wc) { $binCandidates += $wc }

if (-not $binCandidates -or $binCandidates.Count -eq 0) {
    Write-Warning "No binaries found under $RepoRoot (looking for 'whois-*' or 'whois-client')"
} else {
    foreach ($bin in $binCandidates) {
        $name = $bin.BaseName
        $arch = 'unknown'
        if ($name -like 'whois-*' -and $name -ne 'whois-client') {
            $parts = $name.Split('-',2)
            if ($parts.Count -ge 2) { $arch = $parts[1] }
        } elseif ($name -eq 'whois-client') {
            $arch = 'native'
        }
        $archDir = Join-Path $binDir $arch
        if (-not (Test-Path $archDir)) { New-Item -ItemType Directory -Path $archDir | Out-Null }
        Copy-Item $bin.FullName (Join-Path $archDir $bin.Name)
    }
}

# 2) Docs: USAGE_CN.md, USAGE_EN.md, README
$whoisDocs = @(
    (Join-Path $RepoRoot 'docs/USAGE_CN.md'),
    (Join-Path $RepoRoot 'docs/USAGE_EN.md')
)
$readme  = Join-Path $RepoRoot 'README.md'
$license = Join-Path $RepoRoot 'LICENSE'

foreach ($doc in $whoisDocs) { if (Test-Path $doc) { Copy-Item $doc $docsDir } }
if (Test-Path $readme) { Copy-Item $readme (Join-Path $docsDir 'README.repo.md') }

# 3) Source: src/whois_client.c
$clientSrc = Join-Path $RepoRoot 'src/whois_client.c'
if (Test-Path $clientSrc) { Copy-Item $clientSrc $srcDir }

# 4) Licenses
if (Test-Path $license) { Copy-Item $license $licDir }

# 5) Generate SHA256SUMS.txt for all files in package
$hashFile = Join-Path $packageDir 'SHA256SUMS.txt'
if (Test-Path $hashFile) { Remove-Item $hashFile -Force }

Get-ChildItem -File -Recurse $packageDir | ForEach-Object {
    $rel = $_.FullName.Substring($packageDir.Length).TrimStart('\\','/')
    $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
    "{0}  {1}" -f $hash.Hash, $rel | Out-File -FilePath $hashFile -Append -Encoding ascii
}

# 6) Create ZIP archive
$zipPath = Join-Path $OutputRoot ("$packageName.zip")
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $packageDir -DestinationPath $zipPath

Write-Host "[INFO] Package created:" -ForegroundColor Green
Write-Host "       $packageDir" -ForegroundColor Green
Write-Host "       $zipPath" -ForegroundColor Green
