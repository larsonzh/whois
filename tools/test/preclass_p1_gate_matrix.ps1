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
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\preclass_p1_matrix"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$cases = @(
    [pscustomobject]@{ Query = "255.0.0.0"; ExpectR0 = $true;  ExpectR1 = $true;  ExpectCustom = $false },
    [pscustomobject]@{ Query = "10.0.0.1"; ExpectR0 = $false; ExpectR1 = $true;  ExpectCustom = $true },
    [pscustomobject]@{ Query = "fc00::1"; ExpectR0 = $false; ExpectR1 = $true;  ExpectCustom = $false },
    [pscustomobject]@{ Query = "fe80::1"; ExpectR0 = $false; ExpectR1 = $true;  ExpectCustom = $false },
    [pscustomobject]@{ Query = "8.8.8.8"; ExpectR0 = $false; ExpectR1 = $false; ExpectCustom = $false },
    [pscustomobject]@{ Query = "2001:4860:4860::8888"; ExpectR0 = $false; ExpectR1 = $false; ExpectCustom = $false }
)

$modes = @(
    [pscustomobject]@{ Name = "baseline"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_only"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_reserved_r0"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_reserved_r1"; Explicit = $false },
    [pscustomobject]@{ Name = "p1_trial_custom_r0"; Explicit = $false },
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
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Sort-Object Query, Mode | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$failCount = @($rows | Where-Object { -not $_.Pass }).Count
$passCount = @($rows | Where-Object { $_.Pass }).Count

Write-Output ("[PRECLASS-P1] summary_csv={0}" -f $summaryCsv)
Write-Output ("[PRECLASS-P1] summary_txt={0}" -f $summaryTxt)
Write-Output ("[PRECLASS-P1] pass={0} fail={1}" -f $passCount, $failCount)

if ($failCount -gt 0) {
    Write-Output "[PRECLASS-P1] result=fail"
    exit 1
}

Write-Output "[PRECLASS-P1] result=pass"
exit 0
