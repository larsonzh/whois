param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = "",
    [string]$ExplicitHost = "iana"
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\preclass_matrix"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$cases = @(
    [pscustomobject]@{ Query = "255.0.0.0"; ExpectedFamily = "v4" },
    [pscustomobject]@{ Query = "10.0.0.1"; ExpectedFamily = "v4" },
    [pscustomobject]@{ Query = "8.8.8.8"; ExpectedFamily = "v4" },
    [pscustomobject]@{ Query = "fc00::1"; ExpectedFamily = "v6" },
    [pscustomobject]@{ Query = "fe80::1"; ExpectedFamily = "v6" },
    [pscustomobject]@{ Query = "2001:4860:4860::8888"; ExpectedFamily = "v6" }
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

function Test-ImplicitDecision {
    param(
        [string]$Action,
        [string]$RouteChange
    )

    if ($Action -eq "hint-applied") {
        return $RouteChange -eq "1"
    }
    if ($Action -eq "hint-bypassed") {
        return $RouteChange -eq "0"
    }
    if ($Action -eq "step47-short-circuit-unknown") {
        return $RouteChange -eq "1"
    }
    if ($Action -eq "step47-eligible") {
        return $RouteChange -eq "0"
    }

    return $false
}

$rows = @()

Write-Output ("[PRECLASS-MATRIX] out_dir={0}" -f $outDir)
Write-Output ("[PRECLASS-MATRIX] explicit_host={0}" -f $ExplicitHost)
Write-Output ("[PRECLASS-MATRIX] cases={0}" -f $cases.Count)

foreach ($case in $cases) {
    foreach ($mode in @("implicit", "explicit")) {
        $query = $case.Query
        $safe = ($query -replace ':', '-') -replace '/', '_'
        $logPath = Join-Path $outDir ("{0}_{1}.log" -f $mode, $safe)

        Write-Output ("[PRECLASS-MATRIX] running mode={0} query={1}" -f $mode, $query)

        if ($mode -eq "explicit") {
            $raw = & $BinaryPath "--debug" "--retry-metrics" "-h" $ExplicitHost $query 2>&1
        }
        else {
            $raw = & $BinaryPath "--debug" "--retry-metrics" $query 2>&1
        }
        $lines = ConvertTo-NormalizedLine -Raw $raw
        $lines | Out-File -FilePath $logPath -Encoding utf8
        $text = ($lines -join "`n")

        $preclassFamily = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*family=(?<v>[^\s]+)' -GroupName 'v'
        $preclassClass = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*class=(?<v>[^\s]+)' -GroupName 'v'
        $preclassRir = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*rir=(?<v>[^\s]+)' -GroupName 'v'
        $preclassReason = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*reason=(?<v>[^\s]+)' -GroupName 'v'
        $preclassConfidence = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*confidence=(?<v>[^\s]+)' -GroupName 'v'
        $preclassHostMode = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS\][^\r\n]*host_mode=(?<v>[^\s]+)' -GroupName 'v'

        $decisionAction = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*action=(?<v>[^\s]+)' -GroupName 'v'
        $decisionRoute = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*route_change=(?<v>[0-9]+)' -GroupName 'v'
        $decisionHostMode = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*host_mode=(?<v>[^\s]+)' -GroupName 'v'
        $decisionTrial = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*trial=(?<v>[0-9]+)' -GroupName 'v'
        $decisionScope = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*scope=(?<v>[^\s]+)' -GroupName 'v'
        $decisionEarly = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*early_unknown=(?<v>[0-9]+)' -GroupName 'v'
        $decisionDisabled = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*disabled=(?<v>[0-9]+)' -GroupName 'v'

        $preclassFound = ($preclassFamily -ne "" -and $preclassClass -ne "" -and $preclassReason -ne "")
        $decisionFound = ($decisionAction -ne "" -and $decisionRoute -ne "")
        $familyOk = ($preclassFamily -eq $case.ExpectedFamily)
        $hostModeOk = ($preclassHostMode -eq $mode -and $decisionHostMode -eq $mode)
        $confidenceOk = $preclassConfidence -in @("high", "medium", "low")
        $gateOk = ($decisionTrial -eq "0" -and $decisionScope -eq "minimal" -and $decisionEarly -eq "0" -and $decisionDisabled -eq "0")

        $decisionOk = $false
        if ($mode -eq "explicit") {
            $decisionOk = ($decisionAction -eq "hint-bypassed" -and $decisionRoute -eq "0")
        }
        else {
            $decisionOk = Test-ImplicitDecision -Action $decisionAction -RouteChange $decisionRoute
        }

        $pass = $preclassFound -and $decisionFound -and $familyOk -and $hostModeOk -and $confidenceOk -and $gateOk -and $decisionOk

        $rows += [pscustomobject]@{
            Query = $query
            Mode = $mode
            PreclassFound = $preclassFound
            DecisionFound = $decisionFound
            Family = $preclassFamily
            ExpectedFamily = $case.ExpectedFamily
            FamilyOk = $familyOk
            Class = $preclassClass
            Rir = $preclassRir
            Reason = $preclassReason
            Confidence = $preclassConfidence
            ConfidenceOk = $confidenceOk
            PreclassHostMode = $preclassHostMode
            DecisionHostMode = $decisionHostMode
            HostModeOk = $hostModeOk
            Action = $decisionAction
            RouteChange = $decisionRoute
            Trial = $decisionTrial
            Scope = $decisionScope
            EarlyUnknown = $decisionEarly
            Disabled = $decisionDisabled
            GateOk = $gateOk
            DecisionOk = $decisionOk
            Pass = $pass
            Log = $logPath
        }
    }
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Sort-Object Query, Mode | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$failCount = @($rows | Where-Object { -not $_.Pass }).Count
$passCount = @($rows | Where-Object { $_.Pass }).Count

Write-Output ("[PRECLASS-MATRIX] summary_csv={0}" -f $summaryCsv)
Write-Output ("[PRECLASS-MATRIX] summary_txt={0}" -f $summaryTxt)
Write-Output ("[PRECLASS-MATRIX] pass={0} fail={1}" -f $passCount, $failCount)

if ($failCount -gt 0) {
    Write-Output "[PRECLASS-MATRIX] result=fail"
    exit 1
}

Write-Output "[PRECLASS-MATRIX] result=pass"
exit 0
