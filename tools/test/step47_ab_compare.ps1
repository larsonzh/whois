param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = "",
    [string]$Scope = "minimal",
    [switch]$EnableEarlyUnknown,
    [string]$EarlyUnknownList = "",
    [string]$EarlyUnknownListFile = ""
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\step47_ab"
}

$scopeNorm = $Scope.Trim().ToLowerInvariant()
if ($scopeNorm -notin @("minimal", "reserved", "all")) {
    Write-Error "Invalid -Scope '$Scope' (expected minimal|reserved|all)"
    exit 2
}

if ($EarlyUnknownListFile -and $EarlyUnknownListFile.Trim().Length -gt 0) {
    if (-not (Test-Path $EarlyUnknownListFile)) {
        Write-Error "Early unknown list file not found: $EarlyUnknownListFile"
        exit 2
    }

    $lines = Get-Content -Path $EarlyUnknownListFile | ForEach-Object { $_.Trim() } | Where-Object {
        $_.Length -gt 0 -and -not $_.StartsWith("#")
    }
    $EarlyUnknownList = ($lines -join ",")
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$cases = @("255.0.0.0", "10.0.0.1", "fc00::1", "fe80::1", "8.8.8.8")

function Normalize-Lines {
    param([object[]]$Raw)

    return $Raw | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        }
        else {
            $_
        }
    }
}

function Parse-Result {
    param([string]$Text)

    $action = ""
    $route = ""
    $via = ""
    $auth = ""

    $mAction = [regex]::Match($Text, '(?m)^\[PRECLASS-DECISION\].*action=([^\s]+)')
    if ($mAction.Success) { $action = $mAction.Groups[1].Value }

    $mRoute = [regex]::Match($Text, '(?m)^\[PRECLASS-DECISION\].*route_change=([0-9]+)')
    if ($mRoute.Success) { $route = $mRoute.Groups[1].Value }

    $mVia = [regex]::Match($Text, '(?m)^=== Query:.* via ([^ ]+) @')
    if ($mVia.Success) { $via = $mVia.Groups[1].Value }

    $mAuth = [regex]::Match($Text, '(?m)^=== Authoritative RIR: ([^ @=]+)')
    if ($mAuth.Success) { $auth = $mAuth.Groups[1].Value }

    return [pscustomobject]@{
        Action = $action
        RouteChange = $route
        Via = $via
        Authoritative = $auth
    }
}

function Test-InCsv {
    param(
        [string]$Csv,
        [string]$Value
    )

    if (-not $Csv -or $Csv.Trim().Length -eq 0) {
        return $false
    }

    foreach ($raw in ($Csv -split ',')) {
        $token = $raw.Trim()
        if ($token.Length -eq 0) {
            continue
        }
        if ($token.Equals($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

$rows = @()

foreach ($q in $cases) {
    $safe = ($q -replace ':', '-') -replace '/', '_'

    $baseRaw = & $BinaryPath --debug --retry-metrics $q 2>&1
    $baseLines = Normalize-Lines -Raw $baseRaw
    $basePath = Join-Path $outDir ("base_{0}.log" -f $safe)
    $baseLines | Out-File -FilePath $basePath -Encoding utf8
    $baseResult = Parse-Result -Text ($baseLines -join "`n")

    $trialArgs = @("--enable-step47-trial", "--step47-trial-scope", $scopeNorm)
    if ($EnableEarlyUnknown) {
        $trialArgs += "--enable-step47-early-unknown"
        if ($EarlyUnknownList -and $EarlyUnknownList.Trim().Length -gt 0) {
            $trialArgs += @("--step47-early-unknown-list", $EarlyUnknownList)
        }
    }
    $trialArgs += @("--debug", "--retry-metrics", $q)
    $trialRaw = & $BinaryPath @trialArgs 2>&1
    $trialLines = Normalize-Lines -Raw $trialRaw
    $trialPath = Join-Path $outDir ("trial_{0}.log" -f $safe)
    $trialLines | Out-File -FilePath $trialPath -Encoding utf8
    $trialResult = Parse-Result -Text ($trialLines -join "`n")

    $rows += [pscustomobject]@{
        Query = $q
        Scope = $scopeNorm
        BaseAction = $baseResult.Action
        TrialAction = $trialResult.Action
        BaseRoute = $baseResult.RouteChange
        TrialRoute = $trialResult.RouteChange
        BaseVia = $baseResult.Via
        TrialVia = $trialResult.Via
        BaseAuth = $baseResult.Authoritative
        TrialAuth = $trialResult.Authoritative
        AuthUnchanged = ($baseResult.Authoritative -eq $trialResult.Authoritative)
        RouteUnchanged = ($baseResult.RouteChange -eq $trialResult.RouteChange)
    }
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$authChangedCount = @($rows | Where-Object { -not $_.AuthUnchanged }).Count
$routeChangedCount = @($rows | Where-Object { -not $_.RouteUnchanged }).Count
$eligibleCount = @($rows | Where-Object {
    $_.TrialAction -eq "step47-eligible" -or $_.TrialAction -eq "step47-short-circuit-unknown"
}).Count
$shortCircuitCount = @($rows | Where-Object { $_.TrialAction -eq "step47-short-circuit-unknown" }).Count

$expectedAuthChanged = 0
$expectedRouteChanged = 0
if ($EnableEarlyUnknown -and $scopeNorm -eq "reserved") {
    $reservedCases = @("255.0.0.0", "10.0.0.1", "fc00::1", "fe80::1")
    $targetCases = @()
    if (-not $EarlyUnknownList -or $EarlyUnknownList.Trim().Length -eq 0 -or $EarlyUnknownList.Trim().ToLowerInvariant() -eq "default") {
        $targetCases = @("255.0.0.0")
    }
    else {
        foreach ($reservedCase in $reservedCases) {
            if (Test-InCsv -Csv $EarlyUnknownList -Value $reservedCase) {
                $targetCases += $reservedCase
            }
        }
    }

    $expectedRouteChanged = $targetCases.Count
    foreach ($targetCase in $targetCases) {
        $row = $rows | Where-Object { $_.Query -eq $targetCase } | Select-Object -First 1
        if ($null -ne $row -and $row.BaseAuth -ne "unknown") {
            $expectedAuthChanged++
        }
    }
}

Write-Output ("[STEP47-AB] out_dir={0}" -f $outDir)
Write-Output ("[STEP47-AB] scope={0} early_unknown={1} list={2} eligible={3} short_circuit={4} auth_changed={5} route_changed={6}" -f $scopeNorm, ([int][bool]$EnableEarlyUnknown), ($EarlyUnknownList -replace '\s+', ''), $eligibleCount, $shortCircuitCount, $authChangedCount, $routeChangedCount)
Write-Output ("[STEP47-AB] summary_csv={0}" -f $summaryCsv)
Write-Output ("[STEP47-AB] summary_txt={0}" -f $summaryTxt)

if ($authChangedCount -ne $expectedAuthChanged -or $routeChangedCount -ne $expectedRouteChanged) {
    Write-Output "[STEP47-AB] result=fail"
    exit 1
}

Write-Output "[STEP47-AB] result=pass"
exit 0
