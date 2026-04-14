param(
    [ValidateSet("gate-only", "code-change")][string]$Mode = "gate-only",
    [ValidateSet("full", "strict-only")][string]$DevExecutionProfile = "full",
    [ValidateSet("full", "d6-only")][string]$VerifyExecutionProfile = "full",
    [string]$CodeStepCommand = "",
    [ValidateRange(1, 8)][int]$StartRound = 1,
    [ValidateRange(1, 8)][int]$EndRound = 8,
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
    [ValidateSet("true", "false")][string]$QuietRemoteBuildLogs = "false",
    [ValidateSet("true", "false")][string]$QuietTerminalOutput = "true",
    [ValidateSet("0", "1")][string]$RbPreflight = "1",
    [ValidateSet("0", "1")][string]$RbPreclassTableGuard = "1",
    [string]$GitBashPath = "C:\Program Files\Git\bin\bash.exe",
    [ValidateRange(0, 2)][int]$NoDeltaRetryMax = 1,
    [ValidateRange(0, 2)][int]$D6RetryMax = 1,
    [string]$OutDirRoot = "",
    [switch]$EnableGateOnlySourceDrivenSkip,
    [bool]$EnableFastV2Skip = $true,
    [switch]$DisableSourceDrivenSkip
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Format-ElapsedString {
    param([TimeSpan]$Elapsed)

    $hours = [int][Math]::Floor($Elapsed.TotalHours)
    return ("{0:00}:{1:00}:{2:00}.{3:000}" -f $hours, $Elapsed.Minutes, $Elapsed.Seconds, $Elapsed.Milliseconds)
}

function Write-RunTimingSummary {
    param(
        [string]$Tag,
        [datetime]$StartTime
    )

    $endTime = Get-Date
    $elapsed = $endTime - $StartTime
    Write-Output ("[{0}] finished_at={1}" -f $Tag, $endTime.ToString("yyyy-MM-dd HH:mm:ss"))
    Write-Output ("[{0}] elapsed={1} total_seconds={2:N3}" -f $Tag, (Format-ElapsedString -Elapsed $elapsed), $elapsed.TotalSeconds)
}

$runStart = Get-Date
Write-Output ("[AUTOPILOT-8R] started_at={0}" -f $runStart.ToString("yyyy-MM-dd HH:mm:ss"))

if ($StartRound -gt $EndRound) {
    Write-Error "StartRound must be less than or equal to EndRound"
    Write-RunTimingSummary -Tag "AUTOPILOT-8R" -StartTime $runStart
    exit 2
}

$hasDevRound = ($StartRound -le 4)
if ($Mode -eq "code-change" -and $hasDevRound -and [string]::IsNullOrWhiteSpace($CodeStepCommand)) {
    Write-Error "Mode=code-change requires -CodeStepCommand when selected range includes DEV rounds"
    Write-RunTimingSummary -Tag "AUTOPILOT-8R" -StartTime $runStart
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

function Invoke-StreamingCapture {
    param(
        [scriptblock]$Action,
        [bool]$EmitToConsole = $true
    )

    $captured = New-Object System.Collections.Generic.List[string]
    & $Action 2>&1 | ForEach-Object {
        $line = if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        }
        else {
            [string]$_
        }

        [void]$captured.Add($line)
        if ($EmitToConsole) {
            Write-Host $line
        }
    }

    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) {
        $exitCode = 0
    }

    return [pscustomobject]@{
        Raw = @($captured)
        ExitCode = $exitCode
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

function Test-Step47PreflightFlake {
    param(
        [string]$Text,
        [string]$RunOutDir
    )

    if ([regex]::IsMatch($Text, '(?m)^\[STEP47-PREFLIGHT\] pass=3 fail=1\r?$')) {
        return $true
    }

    $logPath = Get-MatchValue -Text $Text -Regex '(?m)^\[ONECLICK-DRYRUN-SMOKE\] log=(.+)$'
    if (-not [string]::IsNullOrWhiteSpace($logPath) -and (Test-Path -LiteralPath $logPath)) {
        $logText = Get-Content -LiteralPath $logPath -Raw
        if ([regex]::IsMatch($logText, '(?m)^\[STEP47-PREFLIGHT\] pass=3 fail=1\r?$')) {
            return $true
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($RunOutDir)) {
        $fallbackLog = Join-Path $RunOutDir 'oneclick_dryrun.log'
        if ((Test-Path -LiteralPath $fallbackLog)) {
            $fallbackText = Get-Content -LiteralPath $fallbackLog -Raw
            if ([regex]::IsMatch($fallbackText, '(?m)^\[STEP47-PREFLIGHT\] pass=3 fail=1\r?$')) {
                return $true
            }
        }
    }

    return $false
}

function Get-TextHash {
    param([string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hashBytes = $sha.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hashBytes)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-SourceScopePatchHash {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $raw = & git -c core.safecrlf=false -c core.autocrlf=false -C $repoRoot diff -- src include 2>&1
    $rc = $LASTEXITCODE
    $normalized = ConvertTo-NormalizedLine -Raw $raw
    $lines = @()
    foreach ($line in $normalized) {
        if ($line -match '^warning: in the working copy of .+ CRLF will be replaced by LF') {
            continue
        }
        $lines += $line
    }
    if ($rc -ne 0) {
        throw "git diff -- src include failed: $($lines -join '; ')"
    }

    $text = ($lines -join "`n")
    return Get-TextHash -Text $text
}

function Get-D1ToD3NoOpCount {
    param([hashtable]$Decisions)

    $count = 0
    foreach ($tag in @("D1", "D2", "D3")) {
        if ($Decisions.ContainsKey($tag) -and $Decisions[$tag] -eq "D-NOP") {
            $count++
        }
    }

    return $count
}

function Invoke-CodeStep {
    param(
        [string]$RoundTag,
        [string]$Phase
    )

    if ($Phase -ne "DEV") {
        return [pscustomobject]@{
            Pass = $true
            ExitCode = 0
            StdoutLog = ""
            Note = "phase=VERIFY"
        }
    }

    if ($Mode -eq "gate-only") {
        return [pscustomobject]@{
            Pass = $true
            ExitCode = 0
            StdoutLog = ""
            Note = "mode=gate-only"
        }
    }

    $emitTerminal = ($QuietTerminalOutput -ne "true")
    $invokeResult = Invoke-StreamingCapture -Action {
        & powershell -NoProfile -ExecutionPolicy Bypass -Command $CodeStepCommand
    } -EmitToConsole:$emitTerminal
    $exitCode = $invokeResult.ExitCode

    $lines = ConvertTo-NormalizedLine -Raw $invokeResult.Raw
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
        $oneClickScript = Join-Path $PSScriptRoot "oneclick_dryrun_guard_smoke.ps1"
        $startLine = ("[AUTOPILOT-8R] oneclick_start round={0} mode={1} attempt={2}" -f $RoundTag, $RunMode, $attempt)
        Write-Output $startLine

        if ($RunMode -eq "local") {
            $oneClickArgs = @{
                Version = $Version
                BuildAndSyncIf = "false"
                QuietTerminalOutput = $QuietTerminalOutput
                GitBashPath = $GitBashPath
                OutDirRoot = $modeOutRoot
            }

            $emitTerminal = ($QuietTerminalOutput -ne "true")
            $invokeResult = Invoke-StreamingCapture -Action { & $oneClickScript @oneClickArgs } -EmitToConsole:$emitTerminal
        }
        else {
            $oneClickArgs = @{
                Version = $Version
                BuildAndSyncIf = "true"
                QuietTerminalOutput = $QuietTerminalOutput
                GitBashPath = $GitBashPath
                RbHost = $RemoteIp
                RbUser = $User
                RbKey = $KeyPath
                RbSmoke = $Smoke
                RbQueries = $RunQueries
                RbGolden = $Golden
                RbOptProfile = $OptProfile
                RbQuietRemote = $QuietRemoteBuildLogs
                RbPreflight = $RbPreflight
                RbPreclassTableGuard = $RbPreclassTableGuard
                RbSyncDir = $SyncDir
                RequireStaticsDetectedIfBuildSync = "false"
                OutDirRoot = $modeOutRoot
            }

            if (-not [string]::IsNullOrWhiteSpace($SmokeArgs)) {
                $oneClickArgs["RbSmokeArgs"] = $SmokeArgs
            }
            if (-not [string]::IsNullOrWhiteSpace($CflagsExtra)) {
                $oneClickArgs["RbCflagsExtra"] = $CflagsExtra
            }

            $emitTerminal = ($QuietTerminalOutput -ne "true")
            $invokeResult = Invoke-StreamingCapture -Action { & $oneClickScript @oneClickArgs } -EmitToConsole:$emitTerminal
        }

        $exitCode = $invokeResult.ExitCode

        $lines = @()
        $lines += $startLine
        $lines += (ConvertTo-NormalizedLine -Raw $invokeResult.Raw)
        $text = ($lines -join "`n")
        $stdoutLog = Join-Path $outDir ("{0}.stdout.log" -f $attemptTag)
        $text | Out-File -FilePath $stdoutLog -Encoding utf8

        $pass = ($exitCode -eq 0) -and [regex]::IsMatch($text, '(?m)^\[ONECLICK-DRYRUN-SMOKE\] result=pass\r?$')
        $runOutDir = Get-MatchValue -Text $text -Regex '(?m)^\[ONECLICK-DRYRUN-SMOKE\] out_dir=(.+)$'
        $endLine = ("[AUTOPILOT-8R] oneclick_end round={0} mode={1} attempt={2} exit={3} pass={4} out_dir={5}" -f $RoundTag, $RunMode, $attempt, $exitCode, $pass, $runOutDir)
        Write-Output $endLine
        $lines += $endLine
        $text = ($lines -join "`n")
        $text | Out-File -FilePath $stdoutLog -Encoding utf8

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
        if ($RunMode -eq "no-delta" -and (Test-Step47PreflightFlake -Text $text -RunOutDir $runOutDir)) {
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
        [string]$RunQueries,
        [ValidateSet("full", "strict-only", "d6-only")][string]$ExecutionProfile
    )

    $attempt = 0
    while ($true) {
        $attempt++
        $attemptTag = "{0}_d6_attempt{1}" -f $RoundTag, $attempt
        $modeOutRoot = Join-Path $outDir $attemptTag
        $d6Script = Join-Path $PSScriptRoot "d6_consistency_double_run.ps1"
        $startLine = ("[AUTOPILOT-8R] d6_start round={0} attempt={1} profile={2}" -f $RoundTag, $attempt, $ExecutionProfile)
        Write-Output $startLine

        $d6Args = @{
            BinaryPath = $BinaryPath
            RemoteIp = $RemoteIp
            User = $User
            KeyPath = $KeyPath
            Smoke = $Smoke
            Queries = $RunQueries
            SyncDir = $SyncDir
            Golden = $Golden
            OptProfile = $OptProfile
            QuietRemote = if ($QuietRemoteBuildLogs -eq "true") { "1" } else { "0" }
            Step47ListFile = $Step47ListFile
            PreclassThresholdFile = $PreclassThresholdFile
            ExecutionProfile = $ExecutionProfile
            BashPath = $GitBashPath
            OutDirRoot = $modeOutRoot
        }

        if (-not [string]::IsNullOrWhiteSpace($SmokeArgs)) {
            $d6Args["SmokeArgs"] = $SmokeArgs
        }
        if (-not [string]::IsNullOrWhiteSpace($CflagsExtra)) {
            $d6Args["CflagsExtra"] = $CflagsExtra
        }

        $emitTerminal = ($QuietTerminalOutput -ne "true")
        $invokeResult = Invoke-StreamingCapture -Action { & $d6Script @d6Args } -EmitToConsole:$emitTerminal

        $exitCode = $invokeResult.ExitCode

        $lines = @()
        $lines += $startLine
        $lines += (ConvertTo-NormalizedLine -Raw $invokeResult.Raw)
        $text = ($lines -join "`n")
        $stdoutLog = Join-Path $outDir ("{0}.stdout.log" -f $attemptTag)
        $text | Out-File -FilePath $stdoutLog -Encoding utf8

        $pass = ($exitCode -eq 0) -and [regex]::IsMatch($text, '(?m)^\[D6-CONSISTENCY\] result=pass\r?$')
        $runOutDir = Get-MatchValue -Text $text -Regex '(?m)^\[D6-CONSISTENCY\] out_dir=(.+)$'
        $endLine = ("[AUTOPILOT-8R] d6_end round={0} attempt={1} exit={2} pass={3} out_dir={4}" -f $RoundTag, $attempt, $exitCode, $pass, $runOutDir)
        Write-Output $endLine
        $lines += $endLine
        $text = ($lines -join "`n")
        $text | Out-File -FilePath $stdoutLog -Encoding utf8

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
$devRoundDecisions = @{}
$globalNoSourceChange = $false
$enableSourceDrivenSkip = (-not $DisableSourceDrivenSkip) -and (
    ($Mode -eq "code-change") -or
    (($Mode -eq "gate-only") -and $EnableGateOnlySourceDrivenSkip)
)

Write-Output ("[AUTOPILOT-8R] round_range={0}-{1}" -f $StartRound, $EndRound)
Write-Output ("[AUTOPILOT-8R] source_driven_skip={0}" -f $(if ($enableSourceDrivenSkip) { "enabled" } else { "disabled" }))
Write-Output ("[AUTOPILOT-8R] dev_execution_profile={0}" -f $DevExecutionProfile)
Write-Output ("[AUTOPILOT-8R] verify_execution_profile={0}" -f $VerifyExecutionProfile)
Write-Output ("[AUTOPILOT-8R] quiet_remote_build_logs={0}" -f $QuietRemoteBuildLogs)
Write-Output ("[AUTOPILOT-8R] quiet_terminal_output={0}" -f $QuietTerminalOutput)
Write-Output ("[AUTOPILOT-8R] rb_preflight={0} rb_table_guard={1}" -f $RbPreflight, $RbPreclassTableGuard)
Write-Output ("[AUTOPILOT-8R] gate_only_source_driven_skip={0}" -f $(if ($EnableGateOnlySourceDrivenSkip) { "enabled" } else { "disabled" }))

for ($round = $StartRound; $round -le $EndRound; $round++) {
    $phase = if ($round -le 4) { "DEV" } else { "VERIFY" }
    $phaseRound = if ($round -le 4) { $round } else { $round - 4 }
    $roundTag = "{0}{1}" -f ($(if ($phase -eq "DEV") { "D" } else { "V" }), $phaseRound)
    $runQueries = if ($phase -eq "VERIFY" -and $phaseRound -eq 3) { $VerifyRound3Queries } else { $Queries }
    $roundExecutionProfile = if ($phase -eq "VERIFY") { $VerifyExecutionProfile } else { $DevExecutionProfile }

    $roundDecision = "EXECUTE"
    $skipReason = ""
    $skipRound = $false
    $sourcePatchHashBefore = ""
    $sourcePatchHashAfterCodeStep = ""
    $sourceDeltaAfterCodeStep = "not-applicable"
    $dNoOpCountBeforeRound = Get-D1ToD3NoOpCount -Decisions $devRoundDecisions
    $hasD1ToD3Decisions = (
        $devRoundDecisions.ContainsKey("D1") -and
        $devRoundDecisions.ContainsKey("D2") -and
        $devRoundDecisions.ContainsKey("D3")
    )

    if ($enableSourceDrivenSkip) {
        if ($phase -eq "VERIFY") {
            if ($globalNoSourceChange) {
                $skipRound = $true
                $roundDecision = "V-SKIP"
                $skipReason = "global-no-source-change"
            }
            elseif ($phaseRound -eq 2 -and $hasD1ToD3Decisions -and $dNoOpCountBeforeRound -eq 0) {
                if (-not $EnableFastV2Skip) {
                    $skipRound = $true
                    $roundDecision = "V-SKIP"
                    $skipReason = "fast-skip-v2-flag-false-d-nop-count-0"
                    Write-Output "[AUTOPILOT-8R] fast_skip_v2=true reason=$skipReason d_nop=$dNoOpCountBeforeRound"
                }
                else {
                    Write-Output "[AUTOPILOT-8R] fast_skip_not_applied=V2 reason=d-nop-count-zero-exec-all-v d_nop=$dNoOpCountBeforeRound"
                }
            }
            elseif ($EnableFastV2Skip -and $phaseRound -eq 2 -and $hasD1ToD3Decisions -and $dNoOpCountBeforeRound -gt 0 -and $dNoOpCountBeforeRound -lt 3) {
                $skipRound = $true
                $roundDecision = "V-SKIP"
                $skipReason = "fast-skip-v2-d-nop-count-$dNoOpCountBeforeRound-of-3"
                Write-Output "[AUTOPILOT-8R] fast_skip_v2=true reason=$skipReason d_nop=$dNoOpCountBeforeRound"
            }
            elseif ($EnableFastV2Skip -and $phaseRound -eq 2 -and $hasD1ToD3Decisions) {
                Write-Output "[AUTOPILOT-8R] fast_skip_not_applied=V2 reason=d-nop-count-out-of-range d_nop=$dNoOpCountBeforeRound"
            }
        }
        elseif ($phase -eq "DEV" -and $phaseRound -eq 4 -and $globalNoSourceChange) {
            $skipRound = $true
            $roundDecision = "D-SKIP"
            $skipReason = "d-nop-count-eq-3"
            $devRoundDecisions[$roundTag] = "D-SKIP"
        }
    }

    Write-Output ("[AUTOPILOT-8R] round_start={0} phase={1} mode={2}" -f $roundTag, $phase, $Mode)

    $codeStep = [pscustomobject]@{
        Pass = $true
        ExitCode = 0
        StdoutLog = ""
        Note = "round-pre-skip"
    }

    if (-not $skipRound) {
        if ($enableSourceDrivenSkip -and $phase -eq "DEV") {
            $sourcePatchHashBefore = Get-SourceScopePatchHash
        }

        $codeStep = Invoke-CodeStep -RoundTag $roundTag -Phase $phase

        if ($enableSourceDrivenSkip -and $phase -eq "DEV") {
            $sourcePatchHashAfterCodeStep = Get-SourceScopePatchHash
            $sourceDeltaAfterCodeStep = if ($sourcePatchHashBefore -eq $sourcePatchHashAfterCodeStep) { "unchanged" } else { "changed" }

            if (-not $codeStep.Pass) {
                $roundDecision = "CODE-STEP-FAIL"
            }
            else {
                $allowDevNoOpSkip = $false
                if ($Mode -eq "code-change") {
                    $allowDevNoOpSkip = ($phaseRound -le 3)
                }
                elseif ($Mode -eq "gate-only" -and $EnableGateOnlySourceDrivenSkip) {
                    # Safety: keep D1 as baseline execution in gate-only mode.
                    $allowDevNoOpSkip = ($phaseRound -ge 2 -and $phaseRound -le 3)
                }

                if ($allowDevNoOpSkip -and $sourceDeltaAfterCodeStep -eq "unchanged") {
                    $skipRound = $true
                    $roundDecision = "D-NOP"
                    $skipReason = "no-source-delta-after-code-step"
                    $devRoundDecisions[$roundTag] = "D-NOP"
                    Write-Output ("[AUTOPILOT-8R] round_nop={0} reason={1}" -f $roundTag, $skipReason)
                }
                else {
                    if ($phaseRound -le 3) {
                        $devRoundDecisions[$roundTag] = "D-CHANGED"
                    }
                    else {
                        $devRoundDecisions[$roundTag] = "D-EXECUTED"
                    }
                }
            }

            if ($phaseRound -eq 3 -and $Mode -eq "code-change") {
                $dNoOpCountAfterD3 = Get-D1ToD3NoOpCount -Decisions $devRoundDecisions
                $allNoOp = ($dNoOpCountAfterD3 -eq 3)
                if ($allNoOp) {
                    $globalNoSourceChange = $true
                    Write-Output "[AUTOPILOT-8R] global_early_stop=true reason=d-nop-count-eq-3 d_nop=$dNoOpCountAfterD3"
                }
            }
        }
    }

    $local = [pscustomobject]@{ Pass = $true; Attempts = 0; ExitCode = 0; OutDir = ""; StdoutLog = ""; RetryReason = "" }
    $noDelta = [pscustomobject]@{ Pass = $true; Attempts = 0; ExitCode = 0; OutDir = ""; StdoutLog = ""; RetryReason = "" }
    $d6 = [pscustomobject]@{ Pass = $true; Attempts = 0; ExitCode = 0; OutDir = ""; StdoutLog = "" }

    if ($roundDecision -eq "CODE-STEP-FAIL") {
        $local.Pass = $false
        $noDelta.Pass = $false
        $d6.Pass = $false
    }
    elseif ($skipRound) {
        Write-Output ("[AUTOPILOT-8R] round_skip={0} decision={1} reason={2}" -f $roundTag, $roundDecision, $skipReason)
    }
    else {
        $runLocalNoDelta = ($roundExecutionProfile -eq "full")

        if ($runLocalNoDelta) {
            $local = Invoke-OneClickRun -RoundTag $roundTag -RunMode "local" -RunQueries $runQueries
            $noDelta = Invoke-OneClickRun -RoundTag $roundTag -RunMode "no-delta" -RunQueries $runQueries
        }
        else {
            $local = [pscustomobject]@{ Pass = $true; Attempts = 0; ExitCode = 0; OutDir = ""; StdoutLog = ""; RetryReason = "skipped-by-verify-profile" }
            $noDelta = [pscustomobject]@{ Pass = $true; Attempts = 0; ExitCode = 0; OutDir = ""; StdoutLog = ""; RetryReason = "skipped-by-verify-profile" }
            Write-Output ("[AUTOPILOT-8R] round_profile={0} profile={1} action=skip-local-no-delta" -f $roundTag, $roundExecutionProfile)
        }

        $d6 = Invoke-D6Run -RoundTag $roundTag -RunQueries $runQueries -ExecutionProfile $roundExecutionProfile
    }

    $roundPass = if ($roundDecision -eq "CODE-STEP-FAIL") {
        $false
    }
    elseif ($skipRound) {
        $true
    }
    else {
        ($codeStep.Pass -and $local.Pass -and $noDelta.Pass -and $d6.Pass)
    }

    $dNoOpCountAfterRound = Get-D1ToD3NoOpCount -Decisions $devRoundDecisions
    $checklistMark = ""
    $checklistComment = ""
    if ($skipRound) {
        $checklistMark = "NOT-RUN"
        $checklistComment = "unexecuted; decision=$roundDecision; reason=$skipReason"
    }
    elseif ($roundDecision -eq "CODE-STEP-FAIL") {
        $checklistMark = "ERROR"
        $checklistComment = "code-step failed before round execution"
    }

    $rows += [pscustomobject]@{
        Round = $round
        Phase = $phase
        RoundTag = $roundTag
        Mode = $Mode
        ExecutionProfile = $roundExecutionProfile
        RoundDecision = $roundDecision
        SkipReason = $skipReason
        Queries = $runQueries
        CodeStepPass = $codeStep.Pass
        CodeStepExit = $codeStep.ExitCode
        CodeStepNote = $codeStep.Note
        SourcePatchHashBefore = $sourcePatchHashBefore
        SourcePatchHashAfterCodeStep = $sourcePatchHashAfterCodeStep
        SourceDeltaAfterCodeStep = $sourceDeltaAfterCodeStep
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
        GlobalNoSourceChange = $globalNoSourceChange
        D1D3NoOpCount = $dNoOpCountAfterRound
        ChecklistMark = $checklistMark
        ChecklistComment = $checklistComment
    }

    $rows | Export-Csv -Path (Join-Path $outDir "summary_partial.csv") -NoTypeInformation -Encoding UTF8

    if (-not $roundPass) {
        Write-Output ("[AUTOPILOT-8R] round_fail={0}" -f $roundTag)
        break
    }

    Write-Output ("[AUTOPILOT-8R] round_pass={0} decision={1}" -f $roundTag, $roundDecision)
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$expectedRoundCount = $EndRound - $StartRound + 1
$allPass = ($rows.Count -eq $expectedRoundCount) -and (@($rows | Where-Object { -not $_.RoundPass }).Count -eq 0)
Write-Output ("[AUTOPILOT-8R] out_dir={0}" -f $outDir)
Write-Output ("[AUTOPILOT-8R] summary_csv={0}" -f $summaryCsv)
Write-Output ("[AUTOPILOT-8R] summary_txt={0}" -f $summaryTxt)

if ($globalNoSourceChange) {
    Write-Output "[AUTOPILOT-8R] final_conclusion=already-applied+unchanged"
    Write-Output "[AUTOPILOT-8R] checklist_backfill_note=unexecuted_rounds_marked_by_ChecklistMark_and_ChecklistComment"
}

$finalResult = if ($allPass) { "pass" } else { "fail" }
$finalExitCode = if ($allPass) { 0 } else { 1 }
$nextRoundReady = $allPass
$finalDecision = if ($nextRoundReady) { "continue-next-round" } else { "stop-and-investigate" }
$failedRoundTags = @($rows | Where-Object { -not $_.RoundPass } | ForEach-Object { $_.RoundTag })

$statusJson = Join-Path $outDir "final_status.json"
$statusTxt = Join-Path $outDir "final_status.txt"
$finalStatus = [ordered]@{
    Script = "AUTOPILOT-8R"
    Result = $finalResult
    ExitCode = $finalExitCode
    NextRoundReady = $nextRoundReady
    FinalDecision = $finalDecision
    ExpectedRoundCount = $expectedRoundCount
    CompletedRoundCount = $rows.Count
    FailedRoundTags = @($failedRoundTags)
    OutDir = $outDir
    SummaryCsv = $summaryCsv
    SummaryTxt = $summaryTxt
    GlobalNoSourceChange = $globalNoSourceChange
    GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

($finalStatus | ConvertTo-Json -Depth 5) | Out-File -FilePath $statusJson -Encoding utf8
@(
    "script=AUTOPILOT-8R"
    "result=$finalResult"
    "exit_code=$finalExitCode"
    "next_round_ready=$(([string]$nextRoundReady).ToLowerInvariant())"
    "final_decision=$finalDecision"
    "out_dir=$outDir"
    "summary_csv=$summaryCsv"
    "summary_txt=$summaryTxt"
    "status_json=$statusJson"
) | Out-File -FilePath $statusTxt -Encoding utf8

Write-Output ("[AUTOPILOT-8R] status_json={0}" -f $statusJson)
Write-Output ("[AUTOPILOT-8R] status_txt={0}" -f $statusTxt)
Write-Output ("[AUTOPILOT-8R] next_round_ready={0}" -f $(([string]$nextRoundReady).ToLowerInvariant()))
Write-Output ("[AUTOPILOT-8R] final_decision={0}" -f $finalDecision)

if ($allPass) {
    Write-Output "[AUTOPILOT-8R] result=pass"
    Write-RunTimingSummary -Tag "AUTOPILOT-8R" -StartTime $runStart
    exit 0
}

Write-Output "[AUTOPILOT-8R] result=fail"
Write-RunTimingSummary -Tag "AUTOPILOT-8R" -StartTime $runStart
exit 1
