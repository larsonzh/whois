param(
    [ValidateSet("gate-only", "code-change")][string]$Mode = "gate-only",
    [string]$CodeStepCommand = "",
    [string]$Version = "3.2.12",
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$RemoteIp = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "/c/Users/妙妙呜/.ssh/id_rsa",
    [string]$Smoke = "1",
    [string]$Queries = "8.8.8.8 1.1.1.1 10.0.0.8",
    [string]$VerifyRound3Queries = "64.6.64.6 103.53.144.0/22 2620:fe::fe",
    [string]$SyncDir = "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois",
    [AllowEmptyString()][string]$SmokeArgs = "",
    [string]$Golden = "1",
    [AllowEmptyString()][string]$CflagsExtra = "",
    [string]$OptProfile = "lto-auto",
    [string]$Step47ListFile = "testdata/step47_reserved_list_default.txt",
    [string]$PreclassThresholdFile = "testdata/preclass_p1_group_thresholds_default.txt",
    [ValidateRange(0, 2)][int]$NoDeltaRetryMax = 1,
    [ValidateRange(0, 2)][int]$D6RetryMax = 1,
    [string]$OutDirRoot = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

if ($Mode -eq "code-change" -and [string]::IsNullOrWhiteSpace($CodeStepCommand)) {
    Write-Error "Mode=code-change requires -CodeStepCommand"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\autopilot_dev_recheck_8round"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

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

function Get-MatchValue {
    param(
        [string]$Text,
        [string]$Regex,
        [int]$GroupIndex = 1
    )

    $m = [regex]::Match($Text, $Regex)
    if ($m.Success) {
        return $m.Groups[$GroupIndex].Value.Trim()
    }
    return ""
}

function Invoke-CodeStep {
    param([string]$RoundTag)

    if ($Mode -eq "gate-only") {
        return [pscustomobject]@{
            Pass = $true
            ExitCode = 0
            StdoutLog = ""
            Note = "mode=gate-only"
        }
    }

    $raw = & powershell -NoProfile -ExecutionPolicy Bypass -Command $CodeStepCommand 2>&1
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) {
        $exitCode = 0
    }

    $lines = ConvertTo-NormalizedLine -Raw $raw
    $text = ($lines -join "`n")
    $stdoutLog = Join-Path $outDir ("{0}_code_step.stdout.log" -f $RoundTag)
    $text | Out-File -FilePath $stdoutLog -Encoding utf8

    return [pscustomobject]@{
        Pass = ($exitCode -eq 0)
        ExitCode = $exitCode
        StdoutLog = $stdoutLog
        Note = "mode=code-change"
    }
}

function Invoke-OneClickRun {
    param(
        [string]$RoundTag,
        [string]$RunMode,
        [string]$RunQueries
    )

    $attempt = 0
    $maxRetry = if ($RunMode -eq "no-delta") { $NoDeltaRetryMax } else { 0 }

    while ($true) {
        $attempt++
        $attemptTag = "{0}_{1}_attempt{2}" -f $RoundTag, $RunMode, $attempt
        $modeOutRoot = Join-Path $outDir $attemptTag

        if ($RunMode -eq "local") {
            $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "oneclick_dryrun_guard_smoke.ps1") `
                -Version $Version `
                -BuildAndSyncIf false `
                -OutDirRoot $modeOutRoot 2>&1
        }
        else {
            $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "oneclick_dryrun_guard_smoke.ps1") `
                -Version $Version `
                -BuildAndSyncIf true `
                -RbHost $RemoteIp `
                -RbUser $User `
                -RbKey $KeyPath `
                -RbSmoke $Smoke `
                -RbQueries $RunQueries `
                -RbSmokeArgs $SmokeArgs `
                -RbGolden $Golden `
                -RbCflagsExtra $CflagsExtra `
                -RbOptProfile $OptProfile `
                -RbPreflight "1" `
                -RbPreclassTableGuard "1" `
                -RbSyncDir $SyncDir `
                -RequireStaticsDetectedIfBuildSync "false" `
                -OutDirRoot $modeOutRoot 2>&1
        }

        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }

        $lines = ConvertTo-NormalizedLine -Raw $raw
        $text = ($lines -join "`n")
        $stdoutLog = Join-Path $outDir ("{0}.stdout.log" -f $attemptTag)
        $text | Out-File -FilePath $stdoutLog -Encoding utf8

        $pass = ($exitCode -eq 0) -and [regex]::IsMatch($text, '(?m)^\[ONECLICK-DRYRUN-SMOKE\] result=pass\r?$')
        $runOutDir = Get-MatchValue -Text $text -Regex '(?m)^\[ONECLICK-DRYRUN-SMOKE\] out_dir=(.+)$'

        if ($pass) {
            return [pscustomobject]@{
                Pass = $true
                Attempts = $attempt
                ExitCode = $exitCode
                OutDir = $runOutDir
                StdoutLog = $stdoutLog
                RetryReason = ""
            }
        }

        $retryReason = ""
        if ($RunMode -eq "no-delta" -and [regex]::IsMatch($text, '(?m)^\[STEP47-PREFLIGHT\] pass=3 fail=1\r?$')) {
            $retryReason = "step47-preflight-flake"
        }

        if ($attempt -gt $maxRetry -or [string]::IsNullOrWhiteSpace($retryReason)) {
            return [pscustomobject]@{
                Pass = $false
                Attempts = $attempt
                ExitCode = $exitCode
                OutDir = $runOutDir
                StdoutLog = $stdoutLog
                RetryReason = $retryReason
            }
        }

        Write-Output ("[AUTOPILOT-8R] retry round={0} mode={1} reason={2}" -f $RoundTag, $RunMode, $retryReason)
    }
}

function Invoke-D6Run {
    param(
        [string]$RoundTag,
        [string]$RunQueries
    )

    $attempt = 0
    while ($true) {
        $attempt++
        $attemptTag = "{0}_d6_attempt{1}" -f $RoundTag, $attempt
        $modeOutRoot = Join-Path $outDir $attemptTag

        $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "d6_consistency_double_run.ps1") `
            -BinaryPath $BinaryPath `
            -RemoteIp $RemoteIp `
            -User $User `
            -KeyPath $KeyPath `
            -Smoke $Smoke `
            -Queries $RunQueries `
            -SyncDir $SyncDir `
            -SmokeArgs $SmokeArgs `
            -Golden $Golden `
            -CflagsExtra $CflagsExtra `
            -OptProfile $OptProfile `
            -Step47ListFile $Step47ListFile `
            -PreclassThresholdFile $PreclassThresholdFile `
            -OutDirRoot $modeOutRoot 2>&1

        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }

        $lines = ConvertTo-NormalizedLine -Raw $raw
        $text = ($lines -join "`n")
        $stdoutLog = Join-Path $outDir ("{0}.stdout.log" -f $attemptTag)
        $text | Out-File -FilePath $stdoutLog -Encoding utf8

        $pass = ($exitCode -eq 0) -and [regex]::IsMatch($text, '(?m)^\[D6-CONSISTENCY\] result=pass\r?$')
        $runOutDir = Get-MatchValue -Text $text -Regex '(?m)^\[D6-CONSISTENCY\] out_dir=(.+)$'

        if ($pass) {
            return [pscustomobject]@{
                Pass = $true
                Attempts = $attempt
                ExitCode = $exitCode
                OutDir = $runOutDir
                StdoutLog = $stdoutLog
            }
        }

        if ($attempt -gt $D6RetryMax) {
            return [pscustomobject]@{
                Pass = $false
                Attempts = $attempt
                ExitCode = $exitCode
                OutDir = $runOutDir
                StdoutLog = $stdoutLog
            }
        }

        Write-Output ("[AUTOPILOT-8R] retry round={0} mode=d6 reason=transient-or-single-round-anomaly" -f $RoundTag)
    }
}

$rows = @()

for ($round = 1; $round -le 8; $round++) {
    $phase = if ($round -le 4) { "DEV" } else { "VERIFY" }
    $phaseRound = if ($round -le 4) { $round } else { $round - 4 }
    $roundTag = "{0}{1}" -f ($(if ($phase -eq "DEV") { "D" } else { "V" }), $phaseRound)
    $runQueries = if ($phase -eq "VERIFY" -and $phaseRound -eq 3) { $VerifyRound3Queries } else { $Queries }

    Write-Output ("[AUTOPILOT-8R] round_start={0} phase={1} mode={2}" -f $roundTag, $phase, $Mode)

    $codeStep = Invoke-CodeStep -RoundTag $roundTag
    $local = Invoke-OneClickRun -RoundTag $roundTag -RunMode "local" -RunQueries $runQueries
    $noDelta = Invoke-OneClickRun -RoundTag $roundTag -RunMode "no-delta" -RunQueries $runQueries
    $d6 = Invoke-D6Run -RoundTag $roundTag -RunQueries $runQueries

    $roundPass = ($codeStep.Pass -and $local.Pass -and $noDelta.Pass -and $d6.Pass)

    $rows += [pscustomobject]@{
        Round = $round
        Phase = $phase
        RoundTag = $roundTag
        Mode = $Mode
        Queries = $runQueries
        CodeStepPass = $codeStep.Pass
        CodeStepExit = $codeStep.ExitCode
        LocalPass = $local.Pass
        LocalAttempts = $local.Attempts
        NoDeltaPass = $noDelta.Pass
        NoDeltaAttempts = $noDelta.Attempts
        NoDeltaRetryReason = $noDelta.RetryReason
        D6Pass = $d6.Pass
        D6Attempts = $d6.Attempts
        RoundPass = $roundPass
        CodeStepStdoutLog = $codeStep.StdoutLog
        LocalOutDir = $local.OutDir
        NoDeltaOutDir = $noDelta.OutDir
        D6OutDir = $d6.OutDir
        LocalStdoutLog = $local.StdoutLog
        NoDeltaStdoutLog = $noDelta.StdoutLog
        D6StdoutLog = $d6.StdoutLog
    }

    $rows | Export-Csv -Path (Join-Path $outDir "summary_partial.csv") -NoTypeInformation -Encoding UTF8

    if (-not $roundPass) {
        Write-Output ("[AUTOPILOT-8R] round_fail={0}" -f $roundTag)
        break
    }

    Write-Output ("[AUTOPILOT-8R] round_pass={0}" -f $roundTag)
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$allPass = ($rows.Count -eq 8) -and (@($rows | Where-Object { -not $_.RoundPass }).Count -eq 0)
Write-Output ("[AUTOPILOT-8R] out_dir={0}" -f $outDir)
Write-Output ("[AUTOPILOT-8R] summary_csv={0}" -f $summaryCsv)
Write-Output ("[AUTOPILOT-8R] summary_txt={0}" -f $summaryTxt)

if ($allPass) {
    Write-Output "[AUTOPILOT-8R] result=pass"
    exit 0
}

Write-Output "[AUTOPILOT-8R] result=fail"
exit 1
