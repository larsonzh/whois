param(
    [string]$GitBashPath = "C:\Program Files\Git\bin\bash.exe",
    [string]$Version = "3.2.12",
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$RemoteIp = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "/c/ssh/id_rsa",
    [string]$Queries = "8.8.8.8 1.1.1.1 10.0.0.8",
    [string]$VerifyRound3Queries = "64.6.64.6 103.53.144.0/22 2620:fe::fe",
    [string]$SyncDir = "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois",
    [string]$Smoke = "1",
    [string]$Golden = "1",
    [AllowEmptyString()][string]$SmokeArgs = "",
    [AllowEmptyString()][string]$CflagsExtra = "",
    [string]$OptProfile = "lto-auto",
    [string]$Step47ListFile = "testdata/step47_reserved_list_default.txt",
    [string]$PreclassThresholdFile = "testdata/preclass_p1_group_thresholds_default.txt",
    [ValidateRange(0, 2)][int]$NoDeltaRetryMax = 1,
    [ValidateRange(0, 2)][int]$D6RetryMax = 1,
    [ValidateRange(1, 8)][int]$StartRound = 1,
    [ValidateRange(1, 8)][int]$EndRound = 8,
    [switch]$ResetCodeStepState,
    [string]$AutopilotOutDirRoot = "d:\LZProjects\whois\out\artifacts\autopilot_dev_recheck_8round",
    [string]$SessionOutDirRoot = "d:\LZProjects\whois\out\artifacts\dev_verify_multiround",
    [string]$CodeStepScript = "tools\test\autopilot_code_step_rounds.ps1",
    [AllowEmptyString()][string]$TaskDefinitionFile = "testdata/autopilot_code_step_tasks_default.json",
    [ValidateSet("full", "d6-only")][string]$VerifyExecutionProfile = "d6-only",
    [bool]$EnableGateOnlySourceDrivenSkip = $true,
    [switch]$DisableSourceDrivenSkip
)

$ErrorActionPreference = "Stop"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

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
Write-Output ("[DEV-VERIFY-MULTI] started_at={0}" -f $runStart.ToString("yyyy-MM-dd HH:mm:ss"))

if ($StartRound -gt $EndRound) {
    throw "StartRound must be less than or equal to EndRound"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$autopilotScript = Join-Path $repoRoot "tools\test\autopilot_dev_recheck_8round.ps1"
$codeStepScriptPath = if ([System.IO.Path]::IsPathRooted($CodeStepScript)) { $CodeStepScript } else { Join-Path $repoRoot $CodeStepScript }
$resolvedTaskDefinitionFile = ""
if (-not [string]::IsNullOrWhiteSpace($TaskDefinitionFile)) {
    $resolvedTaskDefinitionFile = if ([System.IO.Path]::IsPathRooted($TaskDefinitionFile)) { $TaskDefinitionFile } else { Join-Path $repoRoot $TaskDefinitionFile }
}

if (-not (Test-Path -LiteralPath $GitBashPath)) {
    throw "Git Bash not found: $GitBashPath"
}
if (-not (Test-Path -LiteralPath $autopilotScript)) {
    throw "Autopilot script not found: $autopilotScript"
}
if (-not (Test-Path -LiteralPath $codeStepScriptPath)) {
    throw "Code-step script not found: $codeStepScriptPath"
}
if (-not [string]::IsNullOrWhiteSpace($resolvedTaskDefinitionFile) -and -not (Test-Path -LiteralPath $resolvedTaskDefinitionFile)) {
    throw "Task definition file not found: $resolvedTaskDefinitionFile"
}

if ($ResetCodeStepState.IsPresent) {
    if ([string]::IsNullOrWhiteSpace($resolvedTaskDefinitionFile)) {
        & $codeStepScriptPath -Reset
    }
    else {
        & $codeStepScriptPath -Reset -TaskDefinitionFile $resolvedTaskDefinitionFile
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to reset code-step state"
    }
}

$sessionStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionOutDir = Join-Path $SessionOutDirRoot $sessionStamp
New-Item -ItemType Directory -Path $sessionOutDir -Force | Out-Null
$snapshotDir = Join-Path $sessionOutDir "snapshots"
New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null

function ConvertTo-NormalizedLine {
    param([object[]]$Raw)

    $lines = @()
    foreach ($item in $Raw) {
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $lines += $item.Exception.Message
        }
        else {
            $lines += [string]$item
        }
    }

    return $lines
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

function Invoke-CodeStepRound {
    param(
        [string]$RoundTag,
        [string]$ScriptPath,
        [string]$OutDir,
        [AllowEmptyString()][string]$TaskDefinitionFile = ""
    )

    if ([string]::IsNullOrWhiteSpace($TaskDefinitionFile)) {
        $raw = & $ScriptPath 2>&1
    }
    else {
        $raw = & $ScriptPath -TaskDefinitionFile $TaskDefinitionFile 2>&1
    }
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) {
        $exitCode = 0
    }

    $lines = ConvertTo-NormalizedLine -Raw $raw
    foreach ($line in $lines) {
        Write-Output $line
    }

    $logFile = Join-Path $OutDir ("{0}_code_step.log" -f $RoundTag)
    $lines | Out-File -FilePath $logFile -Encoding utf8

    $action = ""
    foreach ($line in $lines) {
        if ($line -match '^\[CODE-STEP\] round=[^ ]+ action=([a-zA-Z0-9-]+)\b') {
            $action = $Matches[1]
            break
        }
    }

    return [pscustomobject]@{
        Pass = ($exitCode -eq 0)
        ExitCode = $exitCode
        Action = $action
        LogFile = $logFile
        Lines = $lines
    }
}

function Get-GitSnapshot {
    param([string]$RepoPath)

    function Invoke-GitCapture {
        param([string[]]$GitArgs)

        $raw = & git -c core.safecrlf=false -c core.autocrlf=false -C $RepoPath @GitArgs 2>&1
        $rc = $LASTEXITCODE
        $lines = @()
        foreach ($item in $raw) {
            $line = if ($item -is [System.Management.Automation.ErrorRecord]) { $item.ToString() } else { [string]$item }
            if ($line -match '^warning: in the working copy of .+ CRLF will be replaced by LF') {
                continue
            }
            if ($line.Trim().Length -gt 0) {
                $lines += $line
            }
        }

        if ($rc -ne 0) {
            throw "git $($GitArgs -join ' ') failed: $($lines -join '; ')"
        }

        return $lines
    }

    $statusLines = @(Invoke-GitCapture -GitArgs @('status', '--short'))
    $headLines = @(Invoke-GitCapture -GitArgs @('rev-parse', 'HEAD'))
    $diffNames = @(Invoke-GitCapture -GitArgs @('diff', '--name-only'))
    $sourceDiffNames = @(Invoke-GitCapture -GitArgs @('diff', '--name-only', '--', 'src', 'include'))
    $sourcePatchLines = @(Invoke-GitCapture -GitArgs @('diff', '--', 'src', 'include'))
    $sourcePatchText = ($sourcePatchLines -join "`n")
    $sourcePatchHash = Get-TextHash -Text $sourcePatchText
    $headLine = if ($headLines.Count -gt 0) { $headLines[0] } else { "" }

    return [pscustomobject]@{
        StatusLines = $statusLines
        Head = [string]$headLine
        DiffNames = $diffNames
        SourceDiffNames = $sourceDiffNames
        SourcePatchHash = $sourcePatchHash
    }
}

function Join-OrNone {
    param([string[]]$Items)

    $normalized = @($Items | Where-Object { $_ -and $_.Trim().Length -gt 0 })
    if ($normalized.Count -eq 0) {
        return "(none)"
    }
    return ($normalized -join ";")
}

function Write-GitSnapshot {
    param(
        [pscustomobject]$Snapshot,
        [string]$Tag
    )

    $statusPath = Join-Path $snapshotDir ("{0}_git_status_short.txt" -f $Tag)
    $headPath = Join-Path $snapshotDir ("{0}_git_head.txt" -f $Tag)
    $diffPath = Join-Path $snapshotDir ("{0}_git_diff_name_only.txt" -f $Tag)
    $sourceDiffPath = Join-Path $snapshotDir ("{0}_git_diff_source_name_only.txt" -f $Tag)
    $sourceHashPath = Join-Path $snapshotDir ("{0}_git_diff_source_hash.txt" -f $Tag)

    @($Snapshot.StatusLines) | Out-File -FilePath $statusPath -Encoding utf8
    @($Snapshot.Head) | Out-File -FilePath $headPath -Encoding utf8
    @($Snapshot.DiffNames) | Out-File -FilePath $diffPath -Encoding utf8
    @($Snapshot.SourceDiffNames) | Out-File -FilePath $sourceDiffPath -Encoding utf8
    @($Snapshot.SourcePatchHash) | Out-File -FilePath $sourceHashPath -Encoding utf8
}

$rows = @()
$devRoundDecisions = @{}
$globalNoSourceChange = $false

for ($round = $StartRound; $round -le $EndRound; $round++) {
    $phase = if ($round -le 4) { "DEV" } else { "VERIFY" }
    $phaseRound = if ($phase -eq "DEV") { $round } else { $round - 4 }
    $roundTag = if ($phase -eq "DEV") { "D$phaseRound" } else { "V$phaseRound" }

    $mode = if ($phase -eq "DEV") { "code-change" } else { "gate-only" }
    $effectiveMode = "gate-only"
    $roundDecision = "EXECUTE"
    $skipReason = ""
    $skipRound = $false
    $autopilotExecuted = $false

    $codeStepExit = 0
    $codeStepAction = ""
    $codeStepLog = ""
    $sourceDeltaAfterCodeStep = "not-applicable"

    $beforeSnapshot = Get-GitSnapshot -RepoPath $repoRoot
    Write-GitSnapshot -Snapshot $beforeSnapshot -Tag ("{0}_before" -f $roundTag)

    $afterCodeStepSnapshot = $beforeSnapshot

    if (-not $DisableSourceDrivenSkip) {
        if ($phase -eq "VERIFY") {
            if ($globalNoSourceChange) {
                $skipRound = $true
                $roundDecision = "V-SKIP"
                $skipReason = "global-no-source-change"
            }
            elseif ($phaseRound -le 3) {
                $mappedDevTag = "D$phaseRound"
                if ($devRoundDecisions.ContainsKey($mappedDevTag) -and $devRoundDecisions[$mappedDevTag] -eq "D-NOP") {
                    $skipRound = $true
                    $roundDecision = "V-SKIP"
                    $skipReason = "mapped-from-$mappedDevTag-d-nop"
                }
            }
        }
        elseif ($phase -eq "DEV" -and $phaseRound -eq 4 -and $globalNoSourceChange) {
            $skipRound = $true
            $roundDecision = "D-SKIP"
            $skipReason = "d1-d3-all-d-nop"
            $devRoundDecisions[$roundTag] = "D-SKIP"
        }
    }

    $lines = @()
    $outDir = ""
    $result = ""
    $exitCode = 0

    if (-not $skipRound -and $phase -eq "DEV") {
        Write-Output ("[DEV-VERIFY-MULTI] code_step_start={0}" -f $roundTag)
        $codeStep = Invoke-CodeStepRound -RoundTag $roundTag -ScriptPath $codeStepScriptPath -OutDir $sessionOutDir -TaskDefinitionFile $resolvedTaskDefinitionFile
        $codeStepExit = $codeStep.ExitCode
        $codeStepAction = if ([string]::IsNullOrWhiteSpace($codeStep.Action)) { "unknown" } else { $codeStep.Action }
        $codeStepLog = $codeStep.LogFile
        $lines += $codeStep.Lines

        $afterCodeStepSnapshot = Get-GitSnapshot -RepoPath $repoRoot
        Write-GitSnapshot -Snapshot $afterCodeStepSnapshot -Tag ("{0}_after_code_step" -f $roundTag)

        $sourceDeltaAfterCodeStep = if ($beforeSnapshot.SourcePatchHash -eq $afterCodeStepSnapshot.SourcePatchHash) {
            "unchanged"
        }
        else {
            "changed"
        }

        if (-not $codeStep.Pass) {
            $roundDecision = "CODE-STEP-FAIL"
        }
        elseif (-not $DisableSourceDrivenSkip -and $phaseRound -le 3 -and $sourceDeltaAfterCodeStep -eq "unchanged") {
            $skipRound = $true
            $roundDecision = "D-NOP"
            $skipReason = "no-source-delta-after-code-step"
            $devRoundDecisions[$roundTag] = "D-NOP"
            $nopLine = ("[DEV-VERIFY-MULTI] round_nop={0} reason={1}" -f $roundTag, $skipReason)
            Write-Output $nopLine
            $lines += $nopLine
        }
        else {
            if ($phaseRound -le 3) {
                $devRoundDecisions[$roundTag] = "D-CHANGED"
            }
            else {
                $devRoundDecisions[$roundTag] = "D-EXECUTED"
            }
        }

        if (-not $DisableSourceDrivenSkip -and $phaseRound -eq 3) {
            $allNoOp = (
                $devRoundDecisions.ContainsKey("D1") -and $devRoundDecisions["D1"] -eq "D-NOP" -and
                $devRoundDecisions.ContainsKey("D2") -and $devRoundDecisions["D2"] -eq "D-NOP" -and
                $devRoundDecisions.ContainsKey("D3") -and $devRoundDecisions["D3"] -eq "D-NOP"
            )
            if ($allNoOp) {
                $globalNoSourceChange = $true
                $globalLine = "[DEV-VERIFY-MULTI] global_early_stop=true reason=d1-d3-all-d-nop"
                Write-Output $globalLine
                $lines += $globalLine
            }
        }
    }

    if (-not $skipRound -and $roundDecision -ne "CODE-STEP-FAIL") {
        $roundVerifyProfile = if ($phase -eq "VERIFY") { $VerifyExecutionProfile } else { "n/a" }
        Write-Output ("[DEV-VERIFY-MULTI] round_start={0} phase={1} mode={2} phase_mode={3} verify_profile={4}" -f $roundTag, $phase, $effectiveMode, $mode, $roundVerifyProfile)

        $autopilotParams = @{
            Mode = $effectiveMode
            VerifyExecutionProfile = $VerifyExecutionProfile
            StartRound = $round
            EndRound = $round
            Version = $Version
            BinaryPath = $BinaryPath
            RemoteIp = $RemoteIp
            User = $User
            KeyPath = $KeyPath
            Smoke = $Smoke
            Queries = $Queries
            VerifyRound3Queries = $VerifyRound3Queries
            SyncDir = $SyncDir
            Golden = $Golden
            OptProfile = $OptProfile
            Step47ListFile = $Step47ListFile
            PreclassThresholdFile = $PreclassThresholdFile
            GitBashPath = $GitBashPath
            NoDeltaRetryMax = $NoDeltaRetryMax
            D6RetryMax = $D6RetryMax
            OutDirRoot = $AutopilotOutDirRoot
        }

        if ($EnableGateOnlySourceDrivenSkip) {
            $autopilotParams["EnableGateOnlySourceDrivenSkip"] = $true
        }

        if (-not [string]::IsNullOrWhiteSpace($SmokeArgs)) {
            $autopilotParams["SmokeArgs"] = $SmokeArgs
        }
        if (-not [string]::IsNullOrWhiteSpace($CflagsExtra)) {
            $autopilotParams["CflagsExtra"] = $CflagsExtra
        }

        $raw = & $autopilotScript @autopilotParams 2>&1
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = 0 }
        $autopilotExecuted = $true

        $runLines = ConvertTo-NormalizedLine -Raw $raw
        foreach ($line in $runLines) {
            Write-Output $line
        }
        $lines += $runLines

        foreach ($line in $runLines) {
            if ($line -match '^\[AUTOPILOT-8R\] out_dir=(.+)$') {
                $outDir = $Matches[1].Trim()
            }
            if ($line -match '^\[AUTOPILOT-8R\] result=(pass|fail)$') {
                $result = $Matches[1]
            }
        }
    }
    elseif ($roundDecision -eq "CODE-STEP-FAIL") {
        $exitCode = if ($codeStepExit -ne 0) { $codeStepExit } else { 1 }
        $result = "fail"
    }
    else {
        $exitCode = 0
        if ($globalNoSourceChange) {
            $result = "no-source-change"
        }
        else {
            $result = "skip"
        }

        $skipLine = ("[DEV-VERIFY-MULTI] round_skip={0} decision={1} reason={2}" -f $roundTag, $roundDecision, $skipReason)
        Write-Output $skipLine
        $lines += $skipLine
    }

    $afterSnapshot = Get-GitSnapshot -RepoPath $repoRoot
    Write-GitSnapshot -Snapshot $afterSnapshot -Tag ("{0}_after" -f $roundTag)

    $beforeStatusCount = @($beforeSnapshot.StatusLines).Count
    $afterStatusCount = @($afterSnapshot.StatusLines).Count
    $beforeDiffNames = Join-OrNone -Items @($beforeSnapshot.DiffNames)
    $afterDiffNames = Join-OrNone -Items @($afterSnapshot.DiffNames)
    $beforeSourceDiffNames = Join-OrNone -Items @($beforeSnapshot.SourceDiffNames)
    $afterCodeStepSourceDiffNames = Join-OrNone -Items @($afterCodeStepSnapshot.SourceDiffNames)
    $afterSourceDiffNames = Join-OrNone -Items @($afterSnapshot.SourceDiffNames)
    $beforeStatusText = (@($beforeSnapshot.StatusLines) -join "`n")
    $afterStatusText = (@($afterSnapshot.StatusLines) -join "`n")
    $snapshotDelta = if (($beforeSnapshot.Head -eq $afterSnapshot.Head) -and
        ($beforeStatusText -eq $afterStatusText) -and
        ($beforeDiffNames -eq $afterDiffNames)) {
        "unchanged"
    }
    else {
        "changed"
    }

    $roundLog = Join-Path $sessionOutDir ("{0}.log" -f $roundTag)
    $lines | Out-File -FilePath $roundLog -Encoding utf8

    $roundPass = if ($roundDecision -eq "CODE-STEP-FAIL") {
        $false
    }
    elseif ($skipRound) {
        $true
    }
    else {
        ($exitCode -eq 0 -and $result -eq "pass")
    }

    if (-not $result -or $result.Trim().Length -eq 0) {
        $result = if ($roundPass) { "pass" } else { "unknown" }
    }

    $rows += [pscustomobject]@{
        Round = $round
        Phase = $phase
        RoundTag = $roundTag
        Mode = $mode
        EffectiveMode = $effectiveMode
        VerifyExecutionProfile = $VerifyExecutionProfile
        RoundDecision = $roundDecision
        SkipReason = $skipReason
        ExitCode = $exitCode
        Result = $result
        RoundPass = $roundPass
        AutopilotExecuted = $autopilotExecuted
        AutopilotOutDir = $outDir
        CodeStepAction = if ($codeStepAction) { $codeStepAction } else { "(none)" }
        CodeStepExit = $codeStepExit
        CodeStepLog = if ($codeStepLog) { $codeStepLog } else { "" }
        BeforeHead = $beforeSnapshot.Head
        AfterHead = $afterSnapshot.Head
        BeforeStatusCount = $beforeStatusCount
        AfterStatusCount = $afterStatusCount
        BeforeDiffNames = $beforeDiffNames
        AfterDiffNames = $afterDiffNames
        BeforeSourceDiffNames = $beforeSourceDiffNames
        AfterCodeStepSourceDiffNames = $afterCodeStepSourceDiffNames
        AfterSourceDiffNames = $afterSourceDiffNames
        SourceDeltaAfterCodeStep = $sourceDeltaAfterCodeStep
        SnapshotDelta = $snapshotDelta
        GlobalNoSourceChange = $globalNoSourceChange
        TaskDefinitionFile = if ($resolvedTaskDefinitionFile) { $resolvedTaskDefinitionFile } else { "(default-in-code-step)" }
        LogFile = $roundLog
    }

    $partialCsv = Join-Path $sessionOutDir "summary_partial.csv"
    $rows | Export-Csv -Path $partialCsv -NoTypeInformation -Encoding UTF8

    if (-not $roundPass) {
        Write-Output ("[DEV-VERIFY-MULTI] round_fail={0}" -f $roundTag)
        break
    }

    Write-Output ("[DEV-VERIFY-MULTI] round_pass={0} decision={1}" -f $roundTag, $roundDecision)
}

$summaryCsv = Join-Path $sessionOutDir "summary.csv"
$summaryTxt = Join-Path $sessionOutDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$expected = $EndRound - $StartRound + 1
$allPass = ($rows.Count -eq $expected) -and (@($rows | Where-Object { -not $_.RoundPass }).Count -eq 0)

Write-Output ("[DEV-VERIFY-MULTI] out_dir={0}" -f $sessionOutDir)
Write-Output ("[DEV-VERIFY-MULTI] summary_csv={0}" -f $summaryCsv)
Write-Output ("[DEV-VERIFY-MULTI] summary_txt={0}" -f $summaryTxt)

if ($allPass) {
    Write-Output "[DEV-VERIFY-MULTI] result=pass"
    Write-RunTimingSummary -Tag "DEV-VERIFY-MULTI" -StartTime $runStart
    exit 0
}

Write-Output "[DEV-VERIFY-MULTI] result=fail"
Write-RunTimingSummary -Tag "DEV-VERIFY-MULTI" -StartTime $runStart
exit 1
