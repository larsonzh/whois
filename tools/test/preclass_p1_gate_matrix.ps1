param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = "",
    [string]$ExplicitHost = "iana",
    [string]$CaseListFile = ""
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\preclass_p1_matrix"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$cases = @(
    [pscustomobject]@{ Query = "255.0.0.0"; ExpectR0 = $true;  ExpectR1 = $true;  ExpectCustom = $false; ExpectCustomMulti = $false; CaseGroup = "seed_reserved_v4" },
    [pscustomobject]@{ Query = "10.0.0.1"; ExpectR0 = $false; ExpectR1 = $true;  ExpectCustom = $true;  ExpectCustomMulti = $true;  CaseGroup = "seed_private_v4" },
    [pscustomobject]@{ Query = "fc00::1"; ExpectR0 = $false; ExpectR1 = $true;  ExpectCustom = $false; ExpectCustomMulti = $true;  CaseGroup = "seed_private_v6" },
    [pscustomobject]@{ Query = "fe80::1"; ExpectR0 = $false; ExpectR1 = $true;  ExpectCustom = $false; ExpectCustomMulti = $false; CaseGroup = "seed_linklocal_v6" },
    [pscustomobject]@{ Query = "8.8.8.8"; ExpectR0 = $false; ExpectR1 = $false; ExpectCustom = $false; ExpectCustomMulti = $false; CaseGroup = "seed_public_v4" },
    [pscustomobject]@{ Query = "2001:4860:4860::8888"; ExpectR0 = $false; ExpectR1 = $false; ExpectCustom = $false; ExpectCustomMulti = $false; CaseGroup = "seed_public_v6" }
)

function Add-CaseIfMissing {
    param(
        [string]$Query,
        [string]$CaseGroup = "external_ip"
    )

    if (-not $Query -or $Query.Trim().Length -eq 0) {
        return $false
    }

    $q = $Query.Trim()
    $exists = $script:cases | Where-Object { $_.Query -ieq $q } | Select-Object -First 1
    if ($null -ne $exists) {
        return $false
    }

    $script:cases += [pscustomobject]@{
        Query = $q
        ExpectR0 = $false
        ExpectR1 = $false
        ExpectCustom = $false
        ExpectCustomMulti = $false
        CaseGroup = $CaseGroup
    }
    return $true
}

$defaultCaseFile = Join-Path $PSScriptRoot "..\..\testdata\preclass_p1_real_samples.txt"
$caseFileSpecified = $PSBoundParameters.ContainsKey("CaseListFile")
if (-not $CaseListFile -or $CaseListFile.Trim().Length -eq 0) {
    $CaseListFile = $defaultCaseFile
}

$addedFromFile = 0
if ($caseFileSpecified -and -not (Test-Path $CaseListFile)) {
    Write-Error "Case list file not found: $CaseListFile"
    exit 2
}

if (Test-Path $CaseListFile) {
    $rawLines = Get-Content -Path $CaseListFile -ErrorAction Stop
    foreach ($line in $rawLines) {
        $entry = $line.Trim()
        $entryGroup = "external_ip"
        $entryQuery = $entry
        if ($entry.Length -eq 0 -or $entry.StartsWith("#")) {
            continue
        }
        if ($entry -match '^(?<g>[A-Za-z0-9_-]+)\s*\|\s*(?<q>[0-9A-Fa-f:.]+)$') {
            $entryGroup = $Matches['g']
            $entryQuery = $Matches['q']
        }
        if ($entryQuery -notmatch '^[0-9A-Fa-f:.]+$') {
            continue
        }
        if ($entryQuery -notmatch '[.:]') {
            continue
        }
        if (Add-CaseIfMissing -Query $entryQuery -CaseGroup $entryGroup) {
            $addedFromFile += 1
        }
    }
    Write-Output ("[PRECLASS-P1] cases_file={0} status=loaded added={1}" -f $CaseListFile, $addedFromFile)
}
else {
    Write-Output ("[PRECLASS-P1] cases_file={0} status=missing optional=1" -f $CaseListFile)
}

$modes = @(
    [pscustomobject]@{ Name = "baseline"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_only"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_reserved_r0"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_reserved_r1"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_custom_r0"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_custom_multi_r0"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_custom_default_r1"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_reserved_r1_explicit"; Explicit = $true }
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

function Invoke-Query {
    param(
        [string]$Binary,
        [pscustomobject]$Mode,
        [string]$Query,
        [string]$ExplicitHostValue
    )

    if ($Mode.Name -eq "p1_trial_reserved_r1_explicit") {
        return (& $Binary "--debug" "--retry-metrics" "--enable-preclass-actions" "--preclass-action-tier" "r1" "--enable-step47-trial" "--step47-trial-scope" "reserved" "-h" $ExplicitHostValue $Query 2>&1)
    }

    if ($Mode.Name -eq "p1_trial_reserved_r1") {
        return (& $Binary "--debug" "--retry-metrics" "--enable-preclass-actions" "--preclass-action-tier" "r1" "--enable-step47-trial" "--step47-trial-scope" "reserved" $Query 2>&1)
    }

    if ($Mode.Name -eq "p1_trial_reserved_r0") {
        return (& $Binary "--debug" "--retry-metrics" "--enable-preclass-actions" "--enable-step47-trial" "--step47-trial-scope" "reserved" $Query 2>&1)
    }

    if ($Mode.Name -eq "p1_trial_custom_r0") {
        return (& $Binary "--debug" "--retry-metrics" "--enable-preclass-actions" "--preclass-action-tier" "r0" "--preclass-action-list" "10.0.0.1" "--enable-step47-trial" "--step47-trial-scope" "reserved" $Query 2>&1)
    }

    if ($Mode.Name -eq "p1_trial_custom_multi_r0") {
        return (& $Binary "--debug" "--retry-metrics" "--enable-preclass-actions" "--preclass-action-tier" "r0" "--preclass-action-list" "10.0.0.1, fc00::1" "--enable-step47-trial" "--step47-trial-scope" "reserved" $Query 2>&1)
    }

    if ($Mode.Name -eq "p1_trial_custom_default_r1") {
        return (& $Binary "--debug" "--retry-metrics" "--enable-preclass-actions" "--preclass-action-tier" "r1" "--preclass-action-list" " default " "--enable-step47-trial" "--step47-trial-scope" "reserved" $Query 2>&1)
    }

    if ($Mode.Name -eq "p1_only") {
        return (& $Binary "--debug" "--retry-metrics" "--enable-preclass-actions" $Query 2>&1)
    }

    return (& $Binary "--debug" "--retry-metrics" $Query 2>&1)
}

$rows = @()

Write-Output ("[PRECLASS-P1] out_dir={0}" -f $outDir)
Write-Output ("[PRECLASS-P1] explicit_host={0}" -f $ExplicitHost)
Write-Output ("[PRECLASS-P1] cases={0} modes={1}" -f $cases.Count, $modes.Count)

foreach ($case in $cases) {
    foreach ($mode in $modes) {
        $query = $case.Query
        $safe = ($query -replace ':', '-') -replace '/', '_'
        $logPath = Join-Path $outDir ("{0}_{1}.log" -f $mode.Name, $safe)

        Write-Output ("[PRECLASS-P1] running mode={0} query={1}" -f $mode.Name, $query)

        $raw = Invoke-Query -Binary $BinaryPath -Mode $mode -Query $query -ExplicitHostValue $ExplicitHost
        $lines = ConvertTo-NormalizedLine -Raw $raw
        $lines | Out-File -FilePath $logPath -Encoding utf8
        $text = ($lines -join "`n")

        $decisionAction = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*action=(?<v>[^\s]+)' -GroupName 'v'
        $decisionRoute = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*route_change=(?<v>[0-9]+)' -GroupName 'v'
        $decisionHostMode = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*host_mode=(?<v>[^\s]+)' -GroupName 'v'
        $decisionTrial = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*trial=(?<v>[0-9]+)' -GroupName 'v'
        $decisionScope = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*scope=(?<v>[^\s]+)' -GroupName 'v'
        $decisionP1 = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*p1_actions=(?<v>[0-9]+)' -GroupName 'v'
        $decisionP1Tier = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*p1_tier=(?<v>[^\s]+)' -GroupName 'v'
        $decisionP1List = Get-FirstMatchValue -Text $text -Pattern '(?m)^\[PRECLASS-DECISION\][^\r\n]*p1_list=(?<v>[^\s]+)' -GroupName 'v'

        $decisionFound = ($decisionAction -ne "" -and $decisionRoute -ne "")
        $hostModeOk = $false
        $trialOk = $false
        $scopeOk = $false
        $p1FlagOk = $false
        $p1TierOk = $false
        $p1ListOk = $false
        $actionOk = $false

        if ($mode.Explicit) {
            $hostModeOk = ($decisionHostMode -eq "explicit")
            $trialOk = ($decisionTrial -eq "1")
            $scopeOk = ($decisionScope -eq "reserved")
            $p1FlagOk = ($decisionP1 -eq "1")
            $p1TierOk = ($decisionP1Tier -eq "r1")
            $p1ListOk = ($decisionP1List -eq "default")
            $actionOk = ($decisionAction -eq "hint-bypassed" -and $decisionRoute -eq "0")
        }
        elseif ($mode.Name -eq "baseline") {
            $hostModeOk = ($decisionHostMode -eq "implicit")
            $trialOk = ($decisionTrial -eq "0")
            $scopeOk = ($decisionScope -eq "minimal")
            $p1FlagOk = ($decisionP1 -eq "0")
            $p1TierOk = ($decisionP1Tier -eq "r0")
            $p1ListOk = ($decisionP1List -eq "default")
            $actionOk = ($decisionAction -ne "preclass-short-circuit-unknown")
        }
        elseif ($mode.Name -eq "p1_only") {
            $hostModeOk = ($decisionHostMode -eq "implicit")
            $trialOk = ($decisionTrial -eq "0")
            $scopeOk = ($decisionScope -eq "minimal")
            $p1FlagOk = ($decisionP1 -eq "1")
            $p1TierOk = ($decisionP1Tier -eq "r0")
            $p1ListOk = ($decisionP1List -eq "default")
            $actionOk = ($decisionAction -ne "preclass-short-circuit-unknown")
        }
        elseif ($mode.Name -eq "p1_trial_reserved_r0") {
            $hostModeOk = ($decisionHostMode -eq "implicit")
            $trialOk = ($decisionTrial -eq "1")
            $scopeOk = ($decisionScope -eq "reserved")
            $p1FlagOk = ($decisionP1 -eq "1")
            $p1TierOk = ($decisionP1Tier -eq "r0")
            $p1ListOk = ($decisionP1List -eq "default")
            if ($case.ExpectR0) {
                $actionOk = ($decisionAction -eq "preclass-short-circuit-unknown" -and $decisionRoute -eq "1")
            }
            else {
                $actionOk = ($decisionAction -ne "preclass-short-circuit-unknown")
            }
        }
        elseif ($mode.Name -eq "p1_trial_custom_r0") {
            $hostModeOk = ($decisionHostMode -eq "implicit")
            $trialOk = ($decisionTrial -eq "1")
            $scopeOk = ($decisionScope -eq "reserved")
            $p1FlagOk = ($decisionP1 -eq "1")
            $p1TierOk = ($decisionP1Tier -eq "r0")
            $p1ListOk = ($decisionP1List -eq "custom")
            if ($case.ExpectCustom) {
                $actionOk = ($decisionAction -eq "preclass-short-circuit-unknown" -and $decisionRoute -eq "1")
            }
            else {
                $actionOk = ($decisionAction -ne "preclass-short-circuit-unknown")
            }
        }
        elseif ($mode.Name -eq "p1_trial_custom_multi_r0") {
            $hostModeOk = ($decisionHostMode -eq "implicit")
            $trialOk = ($decisionTrial -eq "1")
            $scopeOk = ($decisionScope -eq "reserved")
            $p1FlagOk = ($decisionP1 -eq "1")
            $p1TierOk = ($decisionP1Tier -eq "r0")
            $p1ListOk = ($decisionP1List -eq "custom")
            if ($case.ExpectCustomMulti) {
                $actionOk = ($decisionAction -eq "preclass-short-circuit-unknown" -and $decisionRoute -eq "1")
            }
            else {
                $actionOk = ($decisionAction -ne "preclass-short-circuit-unknown")
            }
        }
        elseif ($mode.Name -eq "p1_trial_custom_default_r1") {
            $hostModeOk = ($decisionHostMode -eq "implicit")
            $trialOk = ($decisionTrial -eq "1")
            $scopeOk = ($decisionScope -eq "reserved")
            $p1FlagOk = ($decisionP1 -eq "1")
            $p1TierOk = ($decisionP1Tier -eq "r1")
            $p1ListOk = ($decisionP1List -eq "default")
            if ($case.ExpectR1) {
                $actionOk = ($decisionAction -eq "preclass-short-circuit-unknown" -and $decisionRoute -eq "1")
            }
            else {
                $actionOk = ($decisionAction -ne "preclass-short-circuit-unknown")
            }
        }
        else {
            $hostModeOk = ($decisionHostMode -eq "implicit")
            $trialOk = ($decisionTrial -eq "1")
            $scopeOk = ($decisionScope -eq "reserved")
            $p1FlagOk = ($decisionP1 -eq "1")
            $p1TierOk = ($decisionP1Tier -eq "r1")
            $p1ListOk = ($decisionP1List -eq "default")
            if ($case.ExpectR1) {
                $actionOk = ($decisionAction -eq "preclass-short-circuit-unknown" -and $decisionRoute -eq "1")
            }
            else {
                $actionOk = ($decisionAction -ne "preclass-short-circuit-unknown")
            }
        }

        $pass = $decisionFound -and $hostModeOk -and $trialOk -and $scopeOk -and $p1FlagOk -and $p1TierOk -and $p1ListOk -and $actionOk

        $rows += [pscustomobject]@{
            Query = $query
            CaseGroup = $case.CaseGroup
            Mode = $mode.Name
            DecisionFound = $decisionFound
            Action = $decisionAction
            RouteChange = $decisionRoute
            HostMode = $decisionHostMode
            Trial = $decisionTrial
            Scope = $decisionScope
            P1Actions = $decisionP1
            P1Tier = $decisionP1Tier
            P1List = $decisionP1List
            HostModeOk = $hostModeOk
            TrialOk = $trialOk
            ScopeOk = $scopeOk
            P1FlagOk = $p1FlagOk
            P1TierOk = $p1TierOk
            P1ListOk = $p1ListOk
            ActionOk = $actionOk
            Pass = $pass
            Log = $logPath
        }
    }
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$groupSummaryCsv = Join-Path $outDir "summary_group.csv"
$groupSummaryTxt = Join-Path $outDir "summary_group.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Sort-Object Query, Mode | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$groupRows = @(
    $rows |
        Group-Object CaseGroup |
        ForEach-Object {
            $total = $_.Count
            $passed = @($_.Group | Where-Object { $_.Pass }).Count
            $failed = $total - $passed
            $passRate = if ($total -gt 0) { [Math]::Round(($passed * 100.0) / $total, 2) } else { 0.0 }
            [pscustomobject]@{
                CaseGroup = $_.Name
                Total = $total
                Passed = $passed
                Failed = $failed
                PassRatePct = $passRate
            }
        }
)

$groupRows | Sort-Object CaseGroup | Export-Csv -Path $groupSummaryCsv -NoTypeInformation -Encoding UTF8
$groupRows | Sort-Object CaseGroup | Format-Table -AutoSize | Out-String | Out-File -FilePath $groupSummaryTxt -Encoding utf8

$failCount = @($rows | Where-Object { -not $_.Pass }).Count
$passCount = @($rows | Where-Object { $_.Pass }).Count

Write-Output ("[PRECLASS-P1] summary_csv={0}" -f $summaryCsv)
Write-Output ("[PRECLASS-P1] summary_txt={0}" -f $summaryTxt)
Write-Output ("[PRECLASS-P1] group_summary_csv={0}" -f $groupSummaryCsv)
Write-Output ("[PRECLASS-P1] group_summary_txt={0}" -f $groupSummaryTxt)
Write-Output ("[PRECLASS-P1] pass={0} fail={1}" -f $passCount, $failCount)

foreach ($g in ($groupRows | Sort-Object CaseGroup)) {
    Write-Output ("[PRECLASS-P1-GROUP] group={0} pass={1} fail={2} total={3} pass_pct={4}" -f $g.CaseGroup, $g.Passed, $g.Failed, $g.Total, $g.PassRatePct)
}

if ($failCount -gt 0) {
    Write-Output "[PRECLASS-P1] result=fail"
    exit 1
}

Write-Output "[PRECLASS-P1] result=pass"
exit 0
