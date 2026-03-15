param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = "",
    [switch]$FailOnTargetGap
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\step47_matrix"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

$cases = @(
    [pscustomobject]@{ Query = "255.0.0.0"; ExpectedCurrent = "whois.iana.org"; ExpectedTarget = "unknown"; ClassGroup = "reserved-special" },
    [pscustomobject]@{ Query = "10.0.0.1"; ExpectedCurrent = "unknown"; ExpectedTarget = "unknown"; ClassGroup = "reserved-special" },
    [pscustomobject]@{ Query = "fc00::1"; ExpectedCurrent = "unknown"; ExpectedTarget = "unknown"; ClassGroup = "reserved-special" },
    [pscustomobject]@{ Query = "fe80::1"; ExpectedCurrent = "unknown"; ExpectedTarget = "unknown"; ClassGroup = "reserved-special" },
    [pscustomobject]@{ Query = "8.8.8.8"; ExpectedCurrent = "whois.arin.net"; ExpectedTarget = "whois.arin.net"; ClassGroup = "allocated-baseline" }
)

function ConvertTo-NormalizedLine {
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

function Get-FirstMatchValue {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$GroupName
    )

    $m = [regex]::Match($Text, $Pattern)
    if (-not $m.Success) {
        return ""
    }
    return $m.Groups[$GroupName].Value
}

$rows = @()

Write-Output ("[STEP47] cases={0}" -f $cases.Count)
Write-Output ("[STEP47] out_dir={0}" -f $outDir)

foreach ($case in $cases) {
    $query = $case.Query
    $safe = ($query -replace ':', '-') -replace '/', '_'
    $logPath = Join-Path $outDir ("{0}.log" -f $safe)

    Write-Output ("[STEP47] running query={0}" -f $query)
    $raw = & $BinaryPath --debug --retry-metrics $query 2>&1
    $lines = ConvertTo-NormalizedLine -Raw $raw
    $lines | Out-File -FilePath $logPath -Encoding utf8

    $text = ($lines -join "`n")

    $viaHost = Get-FirstMatchValue -Text $text -Pattern '(?m)^=== Query:.* via (?<v>[^ ]+) @' -GroupName 'v'
    $authoritative = Get-FirstMatchValue -Text $text -Pattern '(?m)^=== Authoritative RIR: (?<v>[^ @=]+)' -GroupName 'v'
    $action = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*action=(?<v>[^\s]+)' -GroupName 'v'
    $routeChange = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*route_change=(?<v>[0-9]+)' -GroupName 'v'
    $preclassClass = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*class=(?<v>[^\s]+)' -GroupName 'v'
    $preclassRir = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*rir=(?<v>[^\s]+)' -GroupName 'v'
    $preclassReason = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*reason=(?<v>[^\s]+)' -GroupName 'v'

    $currentMatch = $authoritative -eq $case.ExpectedCurrent
    $targetGap = $authoritative -ne $case.ExpectedTarget
    $decisionOk = ($action -eq "hint-bypassed" -and $routeChange -eq "0")

    $rows += [pscustomobject]@{
        Query = $query
        ClassGroup = $case.ClassGroup
        PreclassClass = $preclassClass
        PreclassRir = $preclassRir
        PreclassReason = $preclassReason
        Action = $action
        RouteChange = $routeChange
        Via = $viaHost
        Authoritative = $authoritative
        ExpectedCurrent = $case.ExpectedCurrent
        ExpectedTarget = $case.ExpectedTarget
        CurrentMatch = $currentMatch
        TargetGap = $targetGap
        DecisionOk = $decisionOk
        Log = $logPath
    }
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$currentMismatchCount = @($rows | Where-Object { -not $_.CurrentMatch }).Count
$decisionMismatchCount = @($rows | Where-Object { -not $_.DecisionOk }).Count
$targetGapCount = @($rows | Where-Object { $_.TargetGap }).Count

Write-Output ("[STEP47] summary_csv={0}" -f $summaryCsv)
Write-Output ("[STEP47] summary_txt={0}" -f $summaryTxt)
Write-Output ("[STEP47] current_mismatch={0} decision_mismatch={1} target_gap={2}" -f $currentMismatchCount, $decisionMismatchCount, $targetGapCount)

$exitCode = 0
if ($currentMismatchCount -gt 0 -or $decisionMismatchCount -gt 0) {
    $exitCode = 1
}
elseif ($FailOnTargetGap -and $targetGapCount -gt 0) {
    $exitCode = 1
}

if ($exitCode -eq 0) {
    Write-Output "[STEP47] result=pass"
}
else {
    Write-Output "[STEP47] result=fail"
}

exit $exitCode
