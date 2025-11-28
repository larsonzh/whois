param(
    [string]$RemoteHost = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "",
    [string]$Queries = "",
    [string]$SyncDirs = "",
    [string]$SmokeArgs = "--debug --retry-metrics --dns-cache-stats",
    [string]$BatchInput = "testdata/queries.txt",
    [string]$CflagsExtra = "-O3 -s",
    [string]$RemoteExtraArgs = "",
    [string]$GoldenExtraArgs = "",
    [string]$HealthFirstPenalty = "whois.arin.net,whois.iana.org,whois.ripe.net",
    [string]$PlanAPenalty = "whois.arin.net,whois.ripe.net",
    [switch]$SkipRaw,
    [switch]$SkipHealthFirst,
    [switch]$SkipPlanA,
    [switch]$RemoteGolden,
    [switch]$NoGolden,
    [switch]$DryRun,
    [switch]$QuietRemote
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

function Convert-ToMsysPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $normalized = $Path -replace "\\", "/"
    if ($normalized -match '^([A-Za-z]):') {
        $drive = $matches[1].ToLower()
        return "/$drive" + $normalized.Substring(2)
    }
    return $normalized
}

function Convert-ToBashLiteral {
    param([string]$Text)
    if ($null -eq $Text) { return "''" }
    $dq = [char]34
    $replacement = "'" + $dq + "'" + $dq + "'"
    $escaped = $Text -replace "'", $replacement
    return "'" + $escaped + "'"
}

function Convert-ToSafeMsysPath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue) -or $PathValue -eq "NONE") {
        return ""
    }
    if ($PathValue -match "^[\\/]") {
        return $PathValue
    }
    if ($PathValue -match '^[A-Za-z]:') {
        return Convert-ToMsysPath -Path $PathValue
    }
    return $PathValue
}

function Convert-ToSyncArgList {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "DEFAULT" -or $Value -eq "NONE") {
        return ""
    }
    $parts = $Value -split '[;,]'
    $converted = @()
    foreach ($part in $parts) {
        $trimmed = $part.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed -notmatch '^/') {
            $converted += Convert-ToMsysPath -Path $trimmed
        }
        else {
            $converted += $trimmed
        }
    }
    return ($converted -join ";")
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
$repoMsys = Convert-ToMsysPath -Path $repoRoot
$repoQuoted = Convert-ToBashLiteral -Text $repoMsys
$bashExe = 'C:\Program Files\Git\bin\bash.exe'
if (-not (Test-Path -LiteralPath $bashExe)) {
    throw "[suite] Git Bash not found: $bashExe"
}
$syncArg = Convert-ToSyncArgList -Value $SyncDirs
$keyArg = Convert-ToSafeMsysPath -PathValue $KeyPath
$batchInputArg = Convert-ToSafeMsysPath -PathValue $BatchInput
$batchInputFull = ""
if (-not [string]::IsNullOrWhiteSpace($BatchInput) -and $BatchInput -ne "NONE") {
    if ([System.IO.Path]::IsPathRooted($BatchInput)) {
        $batchInputFull = $BatchInput
    }
    else {
        $batchInputFull = Join-Path $repoRoot $BatchInput
    }
    if (-not (Test-Path -LiteralPath $batchInputFull)) {
        throw "[suite] BatchInput file not found: $BatchInput"
    }
}
$artifactsRaw = "out/artifacts/batch_raw"
$artifactsHealth = "out/artifacts/batch_health"
$artifactsPlan = "out/artifacts/batch_plan"
foreach ($dir in @($artifactsRaw, $artifactsHealth, $artifactsPlan)) {
    $fullPath = Join-Path $repoRoot $dir
    if (-not (Test-Path -LiteralPath $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath | Out-Null
    }
}

function Get-LatestLogPath {
    param([string]$RelativeSubdir)
    $base = Join-Path $repoRoot $RelativeSubdir
    if (-not (Test-Path -LiteralPath $base)) {
        throw "[suite] Artifacts directory missing: $base"
    }
    $latest = Get-ChildItem -LiteralPath $base -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "[suite] No timestamped artifacts under $RelativeSubdir"
    }
    $logPath = Join-Path $latest.FullName "build_out/smoke_test.log"
    if (-not (Test-Path -LiteralPath $logPath)) {
        throw "[suite] smoke_test.log not found: $logPath"
    }
    return $logPath
}

function Get-GoldenPresetArgs {
    param([string]$Preset)
    switch ($Preset) {
        "raw" { return @() }
        "health-first" { return @(@{ Flag = "--batch-actions"; Value = "debug-penalize,start-skip,force-last" }) }
        "plan-a" { return @(@{ Flag = "--batch-actions"; Value = "plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize" }) }
        default { throw "[suite] Unknown golden preset: $Preset" }
    }
}

function Invoke-Golden {
    param(
        [string]$Preset,
        [string]$LogPath
    )
    $logMsys = Convert-ToMsysPath -Path $LogPath
    $logQuoted = Convert-ToBashLiteral -Text $logMsys
    $presetArgs = Get-GoldenPresetArgs -Preset $Preset
    $argString = " -l $logQuoted"
    foreach ($arg in $presetArgs) {
        $argString += " " + $arg.Flag + " " + (Convert-ToBashLiteral -Text $arg.Value)
    }
    if (-not [string]::IsNullOrWhiteSpace($GoldenExtraArgs) -and $GoldenExtraArgs -ne "NONE") {
        $argString += " $GoldenExtraArgs"
    }
    $logDir = Split-Path -Parent $LogPath
    $reportPath = Join-Path $logDir "golden_report_$($Preset.Replace(' ','_')).txt"
    $reportMsys = Convert-ToMsysPath -Path $reportPath
    $reportQuoted = Convert-ToBashLiteral -Text $reportMsys
    $cmd = "cd $repoQuoted && ./tools/test/golden_check.sh$argString | tee $reportQuoted"
    Write-Host "[suite] Golden check ($Preset): $cmd" -ForegroundColor DarkGray
    & $bashExe -lc $cmd
    if ($LASTEXITCODE -ne 0) {
        throw "[suite] Golden check failed for preset $Preset"
    }
    Write-Host "[suite] Golden check ($Preset) PASS. Report: $reportPath" -ForegroundColor Green
}

function Invoke-Strategy {
    param(
        [string]$Label,
        [string]$Preset,
        [string]$SmokeArgsValue,
        [string]$FetchSubdir,
        [string]$PenaltyHosts,
        [bool]$NeedsBatchInput,
        [bool]$SkipFlag
    )
    if ($SkipFlag) {
        Write-Host "[suite] Skip $Label (flag set)" -ForegroundColor Yellow
        return $null
    }
    if ($NeedsBatchInput -and [string]::IsNullOrWhiteSpace($batchInputArg)) {
        throw "[suite] $Label requires -BatchInput"
    }
    $argParts = @()
    $argParts += "-H " + (Convert-ToBashLiteral -Text $RemoteHost)
    $argParts += "-u " + (Convert-ToBashLiteral -Text $User)
    if (-not [string]::IsNullOrWhiteSpace($keyArg)) {
        $argParts += "-k " + (Convert-ToBashLiteral -Text $keyArg)
    }
    $argParts += "-r 1"
    $queriesToUse = if ($NeedsBatchInput) { "" } else { $Queries }
    if (-not [string]::IsNullOrWhiteSpace($queriesToUse)) {
        $argParts += "-q " + (Convert-ToBashLiteral -Text $queriesToUse)
    }
    if (-not [string]::IsNullOrWhiteSpace($syncArg)) {
        $argParts += "-s " + (Convert-ToBashLiteral -Text $syncArg)
    }
    $argParts += "-P 1"
    $effectiveSmokeArgs = if ($null -ne $SmokeArgsValue) { $SmokeArgsValue.Trim() } else { "" }
    $argParts += "-a " + (Convert-ToBashLiteral -Text $effectiveSmokeArgs)
    $argParts += "-f " + (Convert-ToBashLiteral -Text $FetchSubdir)
    $argParts += "-E " + (Convert-ToBashLiteral -Text $CflagsExtra)
    $remoteGoldenFlag = if ($RemoteGolden) { "1" } else { "0" }
    $argParts += "-G $remoteGoldenFlag"
    $argParts += "-Y 1"
    if ($NeedsBatchInput) {
        $argParts += "-F " + (Convert-ToBashLiteral -Text $batchInputArg)
    }
    if (-not [string]::IsNullOrWhiteSpace($RemoteExtraArgs) -and $RemoteExtraArgs -ne "NONE") {
        $argParts += $RemoteExtraArgs
    }
    $argString = $argParts -join " "
    $envPrefix = ""
    if (-not [string]::IsNullOrWhiteSpace($PenaltyHosts)) {
        $envPrefix = "WHOIS_BATCH_DEBUG_PENALIZE=" + (Convert-ToBashLiteral -Text $PenaltyHosts) + " "
    }
    $command = "cd $repoQuoted && ${envPrefix}./tools/remote/remote_build_and_test.sh $argString"
    Write-Host "[suite] [$Label] launch: $command" -ForegroundColor DarkGray
    Write-Host "[suite] [$Label] remote build running, please wait..." -ForegroundColor Yellow
    if ($DryRun) {
        Write-Host "[suite] [$Label] dry-run: skipped" -ForegroundColor Yellow
        return $null
    }
    if ($QuietRemote) {
        & $bashExe -lc $command *> $null
    }
    else {
        & $bashExe -lc $command
    }
    if ($LASTEXITCODE -ne 0) {
        throw "[suite] $Label remote_build_and_test.sh failed (rc=$LASTEXITCODE)"
    }
    $logPath = Get-LatestLogPath -RelativeSubdir $FetchSubdir
    Write-Host "[suite] [$Label] latest log: $logPath" -ForegroundColor Cyan
    if (-not $NoGolden) {
        Invoke-Golden -Preset $Preset -LogPath $logPath
    }
    return $logPath
}

$results = @{}
$results["raw"] = Invoke-Strategy -Label "Raw default" -Preset "raw" -SmokeArgsValue $SmokeArgs -FetchSubdir $artifactsRaw -PenaltyHosts "" -NeedsBatchInput $false -SkipFlag $SkipRaw
$results["health-first"] = Invoke-Strategy -Label "Health-first" -Preset "health-first" -SmokeArgsValue ($SmokeArgs + " --batch-strategy health-first") -FetchSubdir $artifactsHealth -PenaltyHosts $HealthFirstPenalty -NeedsBatchInput $true -SkipFlag $SkipHealthFirst
$results["plan-a"] = Invoke-Strategy -Label "Plan-A" -Preset "plan-a" -SmokeArgsValue ($SmokeArgs + " --batch-strategy plan-a") -FetchSubdir $artifactsPlan -PenaltyHosts $PlanAPenalty -NeedsBatchInput $true -SkipFlag $SkipPlanA

Write-Host "[suite] Completed runs:" -ForegroundColor Green
foreach ($key in $results.Keys) {
    $log = $results[$key]
    if ($null -eq $log) {
        Write-Host "  - ${key}: skipped"
    }
    else {
        Write-Host "  - ${key}: $log"
    }
}
