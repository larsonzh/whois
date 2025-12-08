param(
    [string]$RemoteHost = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "",
    [string]$Queries = "8.8.8.8 1.1.1.1",
    [string]$BatchInput = "testdata/queries.txt",
    [string]$SmokeArgs = "--debug --retry-metrics --dns-cache-stats",
    [string]$SmokeExtraArgs = "",
    [string]$SelftestActions = "",
    [string]$CflagsExtra = "-O3 -s",
    [string]$SelftestExpectations = "",
    [string]$ErrorPatterns = "",
    [string]$TagExpectations = "",
    [switch]$SkipRemote,
    [switch]$QuietRemote,
    [switch]$NoGolden,
    [string]$NoGoldenToggle
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

function ConvertTo-OptionalValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }
    $trimmed = $Value.Trim()
    if ($trimmed -ieq "NONE") {
        return ""
    }
    return $Value
}

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

function Get-LatestLogPath {
    param([string]$Subdir)
    $base = Join-Path $repoRoot $Subdir
    if (-not (Test-Path -LiteralPath $base)) {
        throw "[suite-selftest] Artifacts directory missing: $base"
    }
    $latest = Get-ChildItem -LiteralPath $base -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "[suite-selftest] No artifacts found under $Subdir"
    }
    $log = Join-Path $latest.FullName "build_out/smoke_test.log"
    if (-not (Test-Path -LiteralPath $log)) {
        throw "[suite-selftest] smoke_test.log missing: $log"
    }
    return $log
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
$bashExe = 'C:\Program Files\Git\bin\bash.exe'
if (-not (Test-Path -LiteralPath $bashExe)) {
    throw "[suite-selftest] Git Bash not found: $bashExe"
}

$KeyPath = ConvertTo-OptionalValue -Value $KeyPath
$SmokeExtraArgs = ConvertTo-OptionalValue -Value $SmokeExtraArgs
$SelftestActions = ConvertTo-OptionalValue -Value $SelftestActions
$SelftestExpectations = ConvertTo-OptionalValue -Value $SelftestExpectations
$ErrorPatterns = ConvertTo-OptionalValue -Value $ErrorPatterns
$TagExpectations = ConvertTo-OptionalValue -Value $TagExpectations

$noGoldenEffective = $NoGolden.IsPresent
if (-not [string]::IsNullOrWhiteSpace($NoGoldenToggle)) {
    $parsed = $noGoldenEffective
    if ([bool]::TryParse($NoGoldenToggle, [ref]$parsed)) {
        $noGoldenEffective = $parsed
    }
    else {
        throw "[suite-selftest] Invalid -NoGoldenToggle value '$NoGoldenToggle' (use true/false)"
    }
 }

if (-not $SkipRemote) {
    $remoteBatchScript = Join-Path $repoRoot 'tools/test/remote_batch_strategy_suite.ps1'
    if (-not (Test-Path -LiteralPath $remoteBatchScript)) {
        throw "[suite-selftest] remote_batch_strategy_suite.ps1 missing at $remoteBatchScript"
    }
    $remoteParams = @{
        RemoteHost = $RemoteHost
        User = $User
    }
    if (-not [string]::IsNullOrWhiteSpace($KeyPath)) {
        $remoteParams.KeyPath = $KeyPath
    }
    if (-not [string]::IsNullOrWhiteSpace($Queries)) {
        $remoteParams.Queries = $Queries
    }
    if (-not [string]::IsNullOrWhiteSpace($BatchInput)) {
        $remoteParams.BatchInput = $BatchInput
    }
    if (-not [string]::IsNullOrWhiteSpace($SmokeArgs)) {
        $remoteParams.SmokeArgs = $SmokeArgs
    }
    if (-not [string]::IsNullOrWhiteSpace($SmokeExtraArgs)) {
        $remoteParams.SmokeExtraArgs = $SmokeExtraArgs
    }
    if (-not [string]::IsNullOrWhiteSpace($SelftestActions)) {
        $remoteParams.SelftestActions = $SelftestActions
    }
    if (-not [string]::IsNullOrWhiteSpace($CflagsExtra)) {
        $remoteParams.CflagsExtra = $CflagsExtra
    }
    if ($noGoldenEffective) {
        $remoteParams.NoGolden = $true
    }
    if ($QuietRemote) { $remoteParams.QuietRemote = $true }
    Write-Host "[suite-selftest] Launch remote batch suite..." -ForegroundColor Yellow
    & $remoteBatchScript @remoteParams
    if ($LASTEXITCODE -ne 0) {
        throw "[suite-selftest] remote batch suite failed ($LASTEXITCODE)"
    }
}

$artifactMap = [ordered]@{
    'raw' = 'out/artifacts/batch_raw'
    'health-first' = 'out/artifacts/batch_health'
    'plan-a' = 'out/artifacts/batch_plan'
    'plan-b' = 'out/artifacts/batch_planb'
}

$expectList = @()
if (-not [string]::IsNullOrWhiteSpace($SelftestExpectations)) {
    $expectList = $SelftestExpectations.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
}
$actionList = @()
if (-not [string]::IsNullOrWhiteSpace($SelftestActions)) {
    $actionList = $SelftestActions.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
}
# If no explicit expectations but actions are provided, synthesize --expect entries.
# Special case: two items where the second looks like an IPv4 query -> merge into one expect.
if ($expectList.Count -eq 0 -and $actionList.Count -gt 0) {
    $ipv4Regex = '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    if ($actionList.Count -eq 2 -and $actionList[0].Trim() -ne '' -and $actionList[1].Trim() -match $ipv4Regex) {
        $a = $actionList[0].Trim()
        $q = $actionList[1].Trim()
        $expectList = @("action=$a,query=$q")
    }
    else {
        $expectList = @()
        foreach ($act in $actionList) {
            $trimAct = $act.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimAct)) {
                $expectList += "action=$trimAct"
            }
        }
    }
}
$errorList = @()
if (-not [string]::IsNullOrWhiteSpace($ErrorPatterns)) {
    $errorList = $ErrorPatterns.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
}
$tagList = @()
if (-not [string]::IsNullOrWhiteSpace($TagExpectations)) {
    $tagList = $TagExpectations.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
}

$repoMsys = Convert-ToMsysPath -Path $repoRoot
$repoQuoted = Convert-ToBashLiteral -Text $repoMsys

$results = @()
foreach ($entry in $artifactMap.GetEnumerator()) {
    try {
        $logPath = Get-LatestLogPath -Subdir $entry.Value
    }
    catch {
        Write-Host "[suite-selftest] $($entry.Key): skipped ($($_.Exception.Message))" -ForegroundColor Yellow
        continue
    }
    $logMsys = Convert-ToMsysPath -Path $logPath
    $cmdArgs = "./tools/test/golden_check_selftest.sh -l " + (Convert-ToBashLiteral -Text $logMsys)
    foreach ($spec in $expectList) {
        $trimSpec = $spec.Trim()
        if (-not [string]::IsNullOrWhiteSpace($trimSpec)) {
            $cmdArgs += " --expect " + (Convert-ToBashLiteral -Text $trimSpec)
        }
    }
    foreach ($regex in $errorList) {
        $trimRegex = $regex.Trim()
        if (-not [string]::IsNullOrWhiteSpace($trimRegex)) {
            $cmdArgs += " --require-error " + (Convert-ToBashLiteral -Text $trimRegex)
        }
    }
    foreach ($tagSpec in $tagList) {
        $trimTag = $tagSpec.Trim()
        if (-not [string]::IsNullOrWhiteSpace($trimTag)) {
            $parts = $trimTag.Split(':', 2)
            if ($parts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
                Write-Host "[suite-selftest] Invalid tag expectation '$trimTag' (use COMPONENT:regex)" -ForegroundColor Yellow
                continue
            }
            $cmdArgs += " --require-tag " + (Convert-ToBashLiteral -Text $parts[0].Trim()) + " " + (Convert-ToBashLiteral -Text $parts[1].Trim())
        }
    }
    $cmd = "cd $repoQuoted && $cmdArgs"
    Write-Host "[suite-selftest] [$($entry.Key)] golden: $cmd" -ForegroundColor DarkGray
    & $bashExe -lc $cmd
    $rc = $LASTEXITCODE
    $results += [pscustomobject]@{
        Strategy = $entry.Key
        Log = $logPath
        ExitCode = $rc
    }
}

Write-Host "[suite-selftest] Summary:" -ForegroundColor Green
foreach ($result in $results) {
    $status = if ($result.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }
    Write-Host "  - $($result.Strategy): [golden-selftest] $status $($result.Log)"
}

if ($results.Where({ $_.ExitCode -ne 0 }).Count -gt 0) {
    exit 3
}
exit 0
