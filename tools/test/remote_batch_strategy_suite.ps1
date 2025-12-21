param(
    [string]$RemoteHost = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "",
    [string]$Queries = "",
    [string]$SyncDirs = "",
    [string]$SmokeArgs = "--debug --retry-metrics --dns-cache-stats",
    [string]$SmokeExtraArgs = "",
    [string]$BatchInput = "testdata/queries.txt",
    [string]$CflagsExtra = "-O3 -s",
    [string]$RemoteExtraArgs = "",
    [string]$GoldenExtraArgs = "",
    [string]$PrefLabels = "NONE",
    [string]$SelftestActions = "",
    [string]$SelftestExpectations = "",
    [string]$BackoffActions = "NONE",
    [string]$HealthFirstPenalty = "whois.arin.net,whois.iana.org,whois.ripe.net",
    [string]$PlanAPenalty = "whois.arin.net,whois.ripe.net",
    [string]$PlanBPenalty = "whois.arin.net,whois.ripe.net",
    [switch]$SkipRaw,
    [switch]$SkipHealthFirst,
    [switch]$SkipPlanA,
    [switch]$SkipPlanB,
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

function ConvertTo-GlobSafeText {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "NONE") {
        return $Value
    }
    $normalized = $Value -replace "'", "" -replace '"', ""
    return $normalized
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
$artifactsPlanB = "out/artifacts/batch_planb"
foreach ($dir in @($artifactsRaw, $artifactsHealth, $artifactsPlan, $artifactsPlanB)) {
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
        "raw" {
            return @(@{ Flag = "--dns-family-mode"; Value = "interleave-v4-first" },
                     @{ Flag = "--dns-start"; Value = "ipv4" })
        }
        "health-first" {
            return @(@{ Flag = "--batch-actions"; Value = "debug-penalize,start-skip,force-last" },
                     @{ Flag = "--dns-family-mode"; Value = "seq-v4-then-v6" },
                     @{ Flag = "--dns-start"; Value = "ipv4" })
        }
        "plan-a" { return @(@{ Flag = "--batch-actions"; Value = "plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize" }) }
        "plan-b" { return @(@{ Flag = "--batch-actions"; Value = "plan-b-force-start,plan-b-fallback,debug-penalize,start-skip,force-last,force-override" }) }
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
    $useSelftestGolden = ($null -ne $SelftestActions -and -not [string]::IsNullOrWhiteSpace($SelftestActions) -and $SelftestActions -ne "NONE") -or
                         ($null -ne $SelftestExpectations -and -not [string]::IsNullOrWhiteSpace($SelftestExpectations) -and $SelftestExpectations -ne "NONE")
    $logDir = Split-Path -Parent $LogPath
    if ($useSelftestGolden) {
        $argString = " -l $logQuoted"
        if (-not [string]::IsNullOrWhiteSpace($SelftestExpectations) -and $SelftestExpectations -ne "NONE") {
            $expectList = $SelftestExpectations.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
            foreach ($spec in $expectList) {
                $trimmedSpec = $spec.Trim()
                if (-not [string]::IsNullOrWhiteSpace($trimmedSpec)) {
                    $argString += " --expect " + (Convert-ToBashLiteral -Text $trimmedSpec)
                }
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($SelftestActions) -and $SelftestActions -ne "NONE") {
            $actionList = $SelftestActions.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
            $ipv4Regex = '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
            if ($actionList.Count -eq 2 -and $actionList[0].Trim() -ne '' -and $actionList[1].Trim() -match $ipv4Regex) {
                $act = $actionList[0].Trim()
                $q = $actionList[1].Trim()
                $argString += " --expect " + (Convert-ToBashLiteral -Text ("action=$act,query=$q"))
            }
            else {
                foreach ($action in $actionList) {
                    $trimmedAction = $action.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($trimmedAction)) {
                        $argString += " --expect " + (Convert-ToBashLiteral -Text ("action=$trimmedAction"))
                    }
                }
            }
        }
        $reportPath = Join-Path $logDir "golden_selftest_report_$($Preset.Replace(' ','_')).txt"
        $reportMsys = Convert-ToMsysPath -Path $reportPath
        $reportQuoted = Convert-ToBashLiteral -Text $reportMsys
        $cmd = "cd $repoQuoted && set -o pipefail && ./tools/test/golden_check_selftest.sh$argString | tee $reportQuoted"
    }
    else {
        $presetArgs = Get-GoldenPresetArgs -Preset $Preset
        $argString = " -l $logQuoted"
        foreach ($arg in $presetArgs) {
            $argString += " " + $arg.Flag + " " + (Convert-ToBashLiteral -Text $arg.Value)
        }
        if (-not [string]::IsNullOrWhiteSpace($BackoffActions) -and $BackoffActions -ne "NONE") {
            $argString += " --backoff-actions " + (Convert-ToBashLiteral -Text $BackoffActions)
        }
        if (-not [string]::IsNullOrWhiteSpace($SelftestActions) -and $SelftestActions -ne "NONE") {
            $argString += " --selftest-actions " + (Convert-ToBashLiteral -Text $SelftestActions)
        }
        if (-not [string]::IsNullOrWhiteSpace($GoldenExtraArgs) -and $GoldenExtraArgs -ne "NONE") {
            $argString += " $GoldenExtraArgs"
        }
        if (-not [string]::IsNullOrWhiteSpace($PrefLabels) -and $PrefLabels -ne "NONE") {
            $argString += " --pref-labels " + (Convert-ToBashLiteral -Text $PrefLabels)
        }
        $reportPath = Join-Path $logDir "golden_report_$($Preset.Replace(' ','_')).txt"
        $reportMsys = Convert-ToMsysPath -Path $reportPath
        $reportQuoted = Convert-ToBashLiteral -Text $reportMsys
        $cmd = "cd $repoQuoted && set -o pipefail && ./tools/test/golden_check.sh$argString | tee $reportQuoted"
    }
    Write-Host "[suite] Golden check ($Preset): $cmd" -ForegroundColor DarkGray
    & $bashExe -lc $cmd | Out-Host
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-Warning "[suite] Golden check ($Preset) FAILED (rc=$exitCode). Report: $reportPath"
        return [pscustomobject]@{
            Status = "FAIL"
            ReportPath = $reportPath
            ExitCode = $exitCode
        }
    }
    Write-Host "[suite] Golden check ($Preset) PASS. Report: $reportPath" -ForegroundColor Green
    return [pscustomobject]@{
        Status = "PASS"
        ReportPath = $reportPath
        ExitCode = 0
    }
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
    $normalizedSmokeExtra = ConvertTo-GlobSafeText -Value $SmokeExtraArgs
    if (-not [string]::IsNullOrWhiteSpace($normalizedSmokeExtra) -and $normalizedSmokeExtra -ne "NONE") {
        if ([string]::IsNullOrWhiteSpace($effectiveSmokeArgs)) {
            $effectiveSmokeArgs = $normalizedSmokeExtra.Trim()
        }
        else {
            $effectiveSmokeArgs = ($effectiveSmokeArgs + " " + $normalizedSmokeExtra).Trim()
        }
    }
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
    $goldenMeta = $null
    if ($NoGolden) {
        $goldenMeta = [pscustomobject]@{
            Status = "SKIPPED"
            ReportPath = $null
        }
    }
    else {
        $goldenMeta = Invoke-Golden -Preset $Preset -LogPath $logPath
    }
    return [pscustomobject]@{
        LogPath = $logPath
        Golden = $goldenMeta
    }
}

$orderedKeys = @("raw", "health-first", "plan-a", "plan-b")
$results = @{}
$results["raw"] = Invoke-Strategy -Label "Raw default" -Preset "raw" -SmokeArgsValue ($SmokeArgs + " --dns-family-mode interleave-v4-first") -FetchSubdir $artifactsRaw -PenaltyHosts "" -NeedsBatchInput $false -SkipFlag $SkipRaw
$results["health-first"] = Invoke-Strategy -Label "Health-first" -Preset "health-first" -SmokeArgsValue ($SmokeArgs + " --batch-strategy health-first --dns-family-mode seq-v4-then-v6") -FetchSubdir $artifactsHealth -PenaltyHosts $HealthFirstPenalty -NeedsBatchInput $true -SkipFlag $SkipHealthFirst
$results["plan-a"] = Invoke-Strategy -Label "Plan-A" -Preset "plan-a" -SmokeArgsValue ($SmokeArgs + " --batch-strategy plan-a") -FetchSubdir $artifactsPlan -PenaltyHosts $PlanAPenalty -NeedsBatchInput $true -SkipFlag $SkipPlanA
$planBSkip = $SkipPlanB
$results["plan-b"] = Invoke-Strategy -Label "Plan-B" -Preset "plan-b" -SmokeArgsValue ($SmokeArgs + " --batch-strategy plan-b") -FetchSubdir $artifactsPlanB -PenaltyHosts $PlanBPenalty -NeedsBatchInput $true -SkipFlag $planBSkip

$overallPass = $true
Write-Host "[suite] Completed runs:" -ForegroundColor Green
$keysToPrint = $orderedKeys | Where-Object { $results.ContainsKey($_) }
foreach ($key in $keysToPrint) {
    $entry = $results[$key]
    if ($null -eq $entry) {
        Write-Host "  - ${key}: skipped"
        continue
    }
    $statusTag = ""
    $goldenStatus = $null
    $goldenReport = $null
    if ($entry.PSObject.Properties.Match("Golden").Count -gt 0) {
        $goldenMeta = $entry.Golden
        if ($null -ne $goldenMeta) {
            if ($goldenMeta.PSObject.Properties.Match("Status").Count -gt 0) {
                $goldenStatus = $goldenMeta.Status
            }
            if ($goldenMeta.PSObject.Properties.Match("ReportPath").Count -gt 0) {
                $goldenReport = $goldenMeta.ReportPath
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($goldenStatus)) {
        $statusTag = "[golden] " + $goldenStatus
        if ($goldenStatus -eq "FAIL") {
            $overallPass = $false
        }
    }
    $line = "  - ${key}:"
    if (-not [string]::IsNullOrWhiteSpace($statusTag)) {
        $line += " $statusTag"
    }
    $entryLogPath = $null
    if ($entry.PSObject.Properties.Match("LogPath").Count -gt 0) {
        $entryLogPath = $entry.LogPath
    }
    if ($null -ne $entryLogPath -and -not [string]::IsNullOrWhiteSpace($entryLogPath)) {
        $line += " " + $entryLogPath
    }
    Write-Host $line
    if ($null -ne $goldenReport -and -not [string]::IsNullOrWhiteSpace($goldenReport)) {
        Write-Host "      report: $goldenReport"
    }
}

if ($overallPass) {
    Write-Host "[suite] Summary: PASS" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "[suite] Summary: FAIL (see reports above)" -ForegroundColor Red
    exit 3
}
