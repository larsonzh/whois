param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = "",
    [ValidateRange(2, 20)][int]$Cycles = 2
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\preclass_phasec_review"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$cases = @(
    [pscustomobject]@{ Name = "r0-reserved"; Query = "255.0.0.0"; Mode = "enabled"; ExpectedClass = "reserved"; ExpectedConfidence = "high" },
    [pscustomobject]@{ Name = "r1-private-v4"; Query = "10.0.0.1"; Mode = "enabled"; ExpectedClass = "special"; ExpectedConfidence = "high" },
    [pscustomobject]@{ Name = "r1-ula-v6"; Query = "fc00::1"; Mode = "enabled"; ExpectedClass = "special"; ExpectedConfidence = "high" },
    [pscustomobject]@{ Name = "r1-linklocal-v6"; Query = "fe80::1"; Mode = "enabled"; ExpectedClass = "special"; ExpectedConfidence = "high" },
    [pscustomobject]@{ Name = "deny-allocated-control"; Query = "8.8.8.8"; Mode = "deny"; ExpectedClass = "legacy"; ExpectedConfidence = "medium" },
    [pscustomobject]@{ Name = "deny-low-confidence"; Query = "2001:db9::1"; Mode = "deny"; ExpectedClass = "allocated"; ExpectedConfidence = "low" },
    [pscustomobject]@{ Name = "deny-non-ip-low"; Query = "example.test"; Mode = "deny"; ExpectedClass = "non-ip"; ExpectedConfidence = "low" },
    [pscustomobject]@{ Name = "explicit-host-bypass"; Query = "255.0.0.0"; Mode = "explicit"; ExpectedClass = "reserved"; ExpectedConfidence = "high" },
    [pscustomobject]@{ Name = "disable-rollback"; Query = "255.0.0.0"; Mode = "rollback"; ExpectedClass = "reserved"; ExpectedConfidence = "high" },
    [pscustomobject]@{ Name = "default-off"; Query = "255.0.0.0"; Mode = "default"; ExpectedClass = "reserved"; ExpectedConfidence = "high" }
)

function ConvertTo-NormalizedLine {
    param([object[]]$Raw)

    return $Raw | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        }
        else {
            [string]$_
        }
    }
}

function Get-Field {
    param(
        [string]$Text,
        [string]$Tag,
        [string]$Name
    )

    $pattern = '(?m)^\[' + [regex]::Escape($Tag) + '\][^\r\n]*\b' + [regex]::Escape($Name) + '=(?<value>[^\s]+)'
    $match = [regex]::Match($Text, $pattern)
    if ($match.Success) {
        return $match.Groups['value'].Value
    }
    return ""
}

$rows = @()
Write-Output ("[PHASEC-REVIEW] out_dir={0} cycles={1} cases_per_cycle={2}" -f $outDir, $Cycles, $cases.Count)

for ($cycle = 1; $cycle -le $Cycles; $cycle++) {
    foreach ($case in $cases) {
        $cliOptions = @("--debug", "--retry-metrics", "-t", "1", "-Q")
        if ($case.Mode -ne "default") {
            $cliOptions += "--enable-preclass-early-converge"
        }
        if ($case.Mode -eq "explicit") {
            $cliOptions += @("-h", "127.0.0.1")
        }
        if ($case.Mode -eq "rollback") {
            $cliOptions += "--disable-address-preclass"
        }
        $cliOptions += $case.Query

        $raw = & $BinaryPath @cliOptions 2>&1
        $exitCode = $LASTEXITCODE
        $lines = @(ConvertTo-NormalizedLine -Raw $raw)
        $text = $lines -join "`n"
        $safeQuery = (($case.Query -replace ':', '-') -replace '/', '_')
        $logPath = Join-Path $outDir ("cycle{0}_{1}_{2}.log" -f $cycle, $case.Name, $safeQuery)
        [System.IO.File]::WriteAllLines($logPath, $lines, [System.Text.UTF8Encoding]::new($false))

        $class = Get-Field -Text $text -Tag "PRECLASS" -Name "class"
        $rir = Get-Field -Text $text -Tag "PRECLASS" -Name "rir"
        $confidence = Get-Field -Text $text -Tag "PRECLASS" -Name "confidence"
        $hostMode = Get-Field -Text $text -Tag "PRECLASS-DECISION" -Name "host_mode"
        $action = Get-Field -Text $text -Tag "PRECLASS-DECISION" -Name "action"
        $routeChange = Get-Field -Text $text -Tag "PRECLASS-DECISION" -Name "route_change"
        $disabled = Get-Field -Text $text -Tag "PRECLASS-DECISION" -Name "disabled"
        $authorityMatch = [regex]::Match($text, '(?m)^=== Authoritative RIR: (?<value>[^ @=]+)')
        $authority = if ($authorityMatch.Success) { $authorityMatch.Groups['value'].Value } else { "" }

        $classificationOk = ($class -eq $case.ExpectedClass -and $confidence -eq $case.ExpectedConfidence)
        if ($case.Mode -eq "rollback") {
            $classificationOk = ($class -eq "" -and $confidence -eq "")
        }
        $pass = $classificationOk
        $reason = "ok"

        switch ($case.Mode) {
            "enabled" {
                $pass = $pass -and $rir -eq "none" -and
                    $action -eq "preclass-early-converge-unknown" -and
                    $routeChange -eq "1" -and $authority -eq "unknown" -and $exitCode -eq 0
                $reason = "eligible-short-circuit"
            }
            "deny" {
                $pass = $pass -and $action -ne "preclass-early-converge-unknown"
                $reason = "ineligible-preserved"
            }
            "explicit" {
                $pass = $pass -and $hostMode -eq "explicit" -and
                    $action -eq "hint-bypassed" -and $routeChange -eq "0"
                $reason = "explicit-host-bypassed"
            }
            "rollback" {
                $pass = $pass -and $disabled -eq "1" -and
                    $action -ne "preclass-early-converge-unknown" -and $routeChange -eq "0"
                $reason = "global-disable-restored"
            }
            "default" {
                $pass = $pass -and $action -ne "preclass-early-converge-unknown"
                $reason = "default-remains-off"
            }
        }

        $rows += [pscustomobject]@{
            Cycle = $cycle
            Name = $case.Name
            Query = $case.Query
            Mode = $case.Mode
            Class = $class
            Rir = $rir
            Confidence = $confidence
            HostMode = $hostMode
            Action = $action
            RouteChange = $routeChange
            Disabled = $disabled
            Authority = $authority
            ExitCode = $exitCode
            Pass = $pass
            Reason = $reason
            Log = $logPath
        }

        Write-Output ("[PHASEC-REVIEW] cycle={0} case={1} result={2} class={3} rir={4} confidence={5} action={6}" -f
            $cycle, $case.Name, $(if ($pass) { "pass" } else { "fail" }), $class, $rir, $confidence, $action)
    }
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$failedRows = @($rows | Where-Object { -not $_.Pass })
$cycleResults = for ($cycle = 1; $cycle -le $Cycles; $cycle++) {
    $cycleRows = @($rows | Where-Object { $_.Cycle -eq $cycle })
    [pscustomobject]@{
        Cycle = $cycle
        Pass = @($cycleRows | Where-Object { -not $_.Pass }).Count -eq 0
        Passed = @($cycleRows | Where-Object { $_.Pass }).Count
        Failed = @($cycleRows | Where-Object { -not $_.Pass }).Count
    }
}
$summaryLines = @(
    "timestamp=$stamp"
    "binary=$BinaryPath"
    "cycles=$Cycles"
    "cases_per_cycle=$($cases.Count)"
    "passed=$(@($rows | Where-Object { $_.Pass }).Count)"
    "failed=$($failedRows.Count)"
    "result=$(if ($failedRows.Count -eq 0) { 'pass' } else { 'fail' })"
) + @($cycleResults | ForEach-Object { "cycle_$($_.Cycle)=$(if ($_.Pass) { 'pass' } else { 'fail' }) passed=$($_.Passed) failed=$($_.Failed)" })
[System.IO.File]::WriteAllLines($summaryTxt, $summaryLines, [System.Text.UTF8Encoding]::new($false))

Write-Output ("[PHASEC-REVIEW] summary_csv={0}" -f $summaryCsv)
Write-Output ("[PHASEC-REVIEW] summary_txt={0}" -f $summaryTxt)
Write-Output ("[PHASEC-REVIEW] result={0} passed={1} failed={2}" -f
    $(if ($failedRows.Count -eq 0) { "pass" } else { "fail" }),
    @($rows | Where-Object { $_.Pass }).Count,
    $failedRows.Count)

if ($failedRows.Count -gt 0) {
    exit 1
}
exit 0