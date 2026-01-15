param(
  [string]$BinaryPath = "release/lzispro/whois/whois-win64.exe",
  [string]$BatchInput = "testdata/queries.txt",
  [string]$OutDir = "./out/stress",
  [string]$ExtraArgs = "--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first",
  [string]$RequireTags = "[DNS-CACHE-SUM],[NET-PROBE],[RETRY-METRICS]",
  [string]$GoldenExtraArgs = "--skip-header-tail --skip-redirect-line"
)

$ErrorActionPreference = "Stop"

# Normalize sentinel values
if ($ExtraArgs -eq "NONE") { $ExtraArgs = "" }
if ($RequireTags -eq "NONE") { $RequireTags = "" }
if ($GoldenExtraArgs -eq "NONE" -or [string]::IsNullOrWhiteSpace($GoldenExtraArgs)) {
  # Stress run validates stderr tags; skip header/tail/redirect checks by default.
  $GoldenExtraArgs = "--skip-header-tail --skip-redirect-line"
}
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = "./out/stress" }

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $OutDir $timestamp

function Resolve-Existing($path, $root) {
    if ([System.IO.Path]::IsPathRooted($path)) { return (Resolve-Path $path).ToString() }
    return (Resolve-Path (Join-Path $root $path)).ToString()
}

function To-Posix($path) {
  $p = $path -replace '\\', '/'
  if ($p -match '^([A-Za-z]):/(.*)') {
    $drive = $Matches[1].ToLower()
    $rest = $Matches[2]
    return "/$drive/$rest"
  }
  return $p
}

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$rootWin = $root.ToString()
try { $binWin = Resolve-Existing $BinaryPath $rootWin } catch { Write-Error "Binary not found: $BinaryPath"; exit 1 }
try { $batchWin = Resolve-Existing $BatchInput $rootWin } catch { Write-Error "Batch input not found: $BatchInput"; exit 1 }
if ([System.IO.Path]::IsPathRooted($OutDir)) { $outRoot = $OutDir } else { $outRoot = Join-Path $rootWin $OutDir }
$runDirWin = Join-Path $outRoot $timestamp
New-Item -ItemType Directory -Force -Path $runDirWin | Out-Null

Write-Host "[stress-ps] root=$rootWin" -ForegroundColor Yellow
Write-Host "[stress-ps] bin=$binWin" -ForegroundColor Yellow
Write-Host "[stress-ps] input=$batchWin" -ForegroundColor Yellow
Write-Host "[stress-ps] rundir=$runDirWin" -ForegroundColor Yellow

$extraArgsEscaped = $ExtraArgs.Replace('"', '\"')
$requireTagsEscaped = $RequireTags.Replace('"', '\"')
$goldenExtraEscaped = $GoldenExtraArgs.Replace('"', '\"')

$rootPosix = To-Posix $rootWin
$binPosix = To-Posix $binWin
$batchPosix = To-Posix $batchWin
$runDirPosix = To-Posix $runDirWin

$script = @"
#!/usr/bin/env bash
set -e
ROOT="$rootPosix"
BIN="$binPosix"
INPUT="$batchPosix"
RUNDIR="$runDirPosix"
echo "[stress] env root=`$ROOT bin=`$BIN input=`$INPUT rundir=`$RUNDIR"
cd "`$ROOT"
mkdir -p "`$RUNDIR"
OUT="`$RUNDIR/stress_out.log"
ERR="`$RUNDIR/stress_err.log"
echo "[stress] out=`$OUT err=`$ERR"
EXTRA_ARGS="$extraArgsEscaped"
REQ_TAGS="$requireTagsEscaped"
GOLDEN_EXTRA="$goldenExtraEscaped"
echo "[stress] running: `$BIN -B `$EXTRA_ARGS < `$INPUT"
`$BIN -B `$EXTRA_ARGS < "`$INPUT" > "`$OUT" 2> "`$ERR" || { echo "[stress] whois run failed"; exit 1; }
if [ -n "`$REQ_TAGS" ]; then
  echo "[stress] golden_check with require-tags: `$REQ_TAGS"
  tools/test/golden_check.sh --require-tags "`$REQ_TAGS" -l "`$ERR" `$GOLDEN_EXTRA || { echo "[stress] golden_check failed"; exit 1; }
else
  echo "[stress] golden_check (no require-tags)"
  tools/test/golden_check.sh -l "`$ERR" `$GOLDEN_EXTRA || { echo "[stress] golden_check failed"; exit 1; }
fi
echo "[stress] done. stdout: `$OUT"
echo "[stress] done. stderr: `$ERR"
"@

$bashScriptWin = Join-Path $runDirWin "run_stress.sh"
[System.IO.File]::WriteAllText($bashScriptWin, $script.Replace("`r`n","`n"), (New-Object System.Text.UTF8Encoding $false))
$bashExe = "C:\\Program Files\\Git\\bin\\bash.exe"
$bashScriptPosix = To-Posix $bashScriptWin

Write-Host "[stress-ps] invoking bash..." -ForegroundColor Yellow
Write-Host "[stress-ps] script file: $bashScriptWin" -ForegroundColor Yellow
Write-Host "[stress-ps] script content (first lines):" -ForegroundColor Yellow
$script.Split("`n") | Select-Object -First 5 | ForEach-Object { Write-Host "[stress-ps]   $_" -ForegroundColor Yellow }

& $bashExe -lc "bash '$bashScriptPosix'"
Write-Host "[stress-ps] bash exit code: $LASTEXITCODE" -ForegroundColor Yellow
Write-Host "[stress-ps] listing rundir:" -ForegroundColor Yellow
Get-ChildItem -Force $runDirWin | ForEach-Object { Write-Host "[stress-ps]   $_" -ForegroundColor Yellow }
