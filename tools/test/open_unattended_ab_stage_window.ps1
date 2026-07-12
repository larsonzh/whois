param(
    [ValidateSet('A', 'B')][string]$Stage,
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20261116-20261130.md',
    [switch]$StartMonitors,
    [switch]$SkipMonitorRestart,
    [switch]$EnableBMonitorRestart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'OPEN-AB-STAGE'
$PSDefaultParameterValues['Invoke-KeyValueFileValueUpdateCore:CommitMode'] = 'Copy'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

# When StartMonitors is requested and the current process is running inside a
# VS Code integrated terminal (parent process is Code.exe), relaunch into a new
# external PowerShell window via Start-Process.  This decouples the long-running
# post-launch workflow (Resolve-CurrentStageRunDir polling, monitor chain startup)
# from the integrated-terminal lifecycle — the external window survives terminal
# timeout and subsequent commands in the same integrated-terminal session.
if ($StartMonitors.IsPresent) {
    $parentProcessId = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue).ParentProcessId
    $parentProcessName = if ($parentProcessId -gt 0) { (Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue).ProcessName } else { '' }
    $isVsCodeTerminal = ($parentProcessName -eq 'Code') -or ($parentProcessName -eq 'Code.exe')

    if ($isVsCodeTerminal) {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        $resolvedStartFile = if ([System.IO.Path]::IsPathRooted($StartFile)) {
            [System.IO.Path]::GetFullPath($StartFile)
        } else {
            [System.IO.Path]::GetFullPath((Join-Path $repoRoot $StartFile))
        }

        $argList = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $PSScriptRoot 'open_unattended_ab_stage_window.ps1'),
            '-Stage', $Stage,
            '-StartFile', "`"$resolvedStartFile`"",
            '-StartMonitors'
        )
        if ($SkipMonitorRestart.IsPresent) { $argList += '-SkipMonitorRestart' }
        if ($EnableBMonitorRestart.IsPresent) { $argList += '-EnableBMonitorRestart' }

        $null = Start-Process -FilePath 'powershell.exe' -WorkingDirectory $repoRoot -ArgumentList $argList -WindowStyle Normal
        Write-Output ('[OPEN-AB-STAGE] relaunched_to_new_window stage={0} parent=Code parent_pid={1}' -f $Stage, $parentProcessId)
        exit 0
    }
}

$dispatchPolicyModulePath = Join-Path $PSScriptRoot 'chat_dispatch_policy_compiler.ps1'
if (-not (Test-Path -LiteralPath $dispatchPolicyModulePath)) {
    throw "Missing script: $dispatchPolicyModulePath"
}
. $dispatchPolicyModulePath

function Get-CurrentSourceDiffSet {
    param([string]$RepoRoot)

    $gitWarningPattern = '^\s*(warning:|git(\.exe)?\s*:\s*warning:)'
    $lines = @()
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Native git stderr warning should not abort stage bootstrap under strict Stop mode.
        $ErrorActionPreference = 'Continue'
        $lines = @((& git -C $RepoRoot diff --name-only -- src include 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        if ($exitCode -ne 0) {
            $detailLines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            $detail = if ($detailLines.Count -gt 0) { $detailLines -join ' | ' } else { 'no-output' }
            throw ("git diff --name-only failed exit={0} detail={1}" -f $exitCode, $detail)
        }
    }
    catch {
        throw ("failed to collect current source diff set: {0}" -f $_.Exception.Message)
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    $result = New-Object 'System.Collections.Generic.List[string]'
    foreach ($raw in $lines) {
        if ([string]::IsNullOrWhiteSpace($raw)) {
            continue
        }

        $line = ([string]$raw).Trim()
        if ($line -match $gitWarningPattern) {
            continue
        }

        $normalized = $line.Replace('\\', '/').Trim()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        [void]$result.Add($normalized)
    }

    return @($result | Sort-Object -Unique)
}

function Test-BNormalModeSourceAlignedWithSnapshot {
    param(
        [string]$RepoRoot,
        [string]$SnapshotDir
    )

    $sourceDir = Join-Path $SnapshotDir 'source'
    if (-not (Test-Path -LiteralPath $sourceDir)) {
        throw "snapshot source directory missing: $sourceDir"
    }

    $sourceFilesPath = Join-Path $SnapshotDir 'source_files.txt'
    $snapshotPaths = New-Object 'System.Collections.Generic.List[string]'

    if (Test-Path -LiteralPath $sourceFilesPath) {
        foreach ($raw in @(Get-Content -LiteralPath $sourceFilesPath -Encoding utf8 -ErrorAction Stop)) {
            if ([string]::IsNullOrWhiteSpace([string]$raw)) {
                continue
            }

                $normalized = ([string]$raw).Trim().TrimStart([char]0xFEFF).Replace('\\', '/').Trim()
            if ([string]::IsNullOrWhiteSpace($normalized)) {
                continue
            }

            [void]$snapshotPaths.Add($normalized)
        }
    }
    else {
        $sourceDirFull = [System.IO.Path]::GetFullPath($sourceDir)
        foreach ($file in @(Get-ChildItem -LiteralPath $sourceDir -File -Recurse -ErrorAction SilentlyContinue)) {
            $relative = $file.FullName.Substring($sourceDirFull.Length).TrimStart('\\').Replace('\\', '/')
            if ([string]::IsNullOrWhiteSpace($relative)) {
                continue
            }

            [void]$snapshotPaths.Add($relative)
        }
    }

    $snapshotList = @($snapshotPaths | Sort-Object -Unique)
    $currentList = @(Get-CurrentSourceDiffSet -RepoRoot $RepoRoot)

    $snapshotSet = @{}
    foreach ($path in $snapshotList) {
        $snapshotSet[[string]$path] = $true
    }

    $currentSet = @{}
    foreach ($path in $currentList) {
        $currentSet[[string]$path] = $true
    }

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $snapshotList) {
        if (-not $currentSet.ContainsKey([string]$path)) {
            [void]$missing.Add([string]$path)
        }
    }

    $extra = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $currentList) {
        if (-not $snapshotSet.ContainsKey([string]$path)) {
            [void]$extra.Add([string]$path)
        }
    }

    $contentMismatches = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $snapshotList) {
        if (-not $currentSet.ContainsKey([string]$path)) {
            continue
        }

        $relativeWindows = ([string]$path).Replace('/', '\\')
        $snapshotFile = Join-Path $sourceDir $relativeWindows
        $currentFile = Join-Path $RepoRoot $relativeWindows

        if (-not (Test-Path -LiteralPath $snapshotFile) -or -not (Test-Path -LiteralPath $currentFile)) {
            [void]$contentMismatches.Add([string]$path)
            continue
        }

        $snapshotHash = (Get-FileHash -LiteralPath $snapshotFile -Algorithm SHA256).Hash
        $currentHash = (Get-FileHash -LiteralPath $currentFile -Algorithm SHA256).Hash
        if ($snapshotHash -ne $currentHash) {
            [void]$contentMismatches.Add([string]$path)
        }
    }

    $match = ($missing.Count -eq 0 -and $extra.Count -eq 0 -and $contentMismatches.Count -eq 0)
    return [pscustomobject]@{
        Match = [bool]$match
        SnapshotCount = [int]$snapshotList.Count
        CurrentCount = [int]$currentList.Count
        MissingCount = [int]$missing.Count
        ExtraCount = [int]$extra.Count
        ContentMismatchCount = [int]$contentMismatches.Count
        Missing = @($missing)
        Extra = @($extra)
        ContentMismatches = @($contentMismatches)
    }
}

function Read-StageFinalStatusEvidence {
    param([AllowEmptyString()][string]$StatusPath)

    $result = [ordered]@{
        Exists = $false
        ParseOk = $false
        Result = ''
        ExitCode = $null
        ExpectedRoundCount = $null
        CompletedRoundCount = $null
        CountsConsistent = $true
        IsPass = $false
        Detail = ''
    }

    if ([string]::IsNullOrWhiteSpace($StatusPath) -or -not (Test-Path -LiteralPath $StatusPath)) {
        return [pscustomobject]$result
    }

    $result.Exists = $true
    $extension = [System.IO.Path]::GetExtension($StatusPath)

    try {
        if ($extension -ieq '.json') {
            $json = Get-Content -LiteralPath $StatusPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            $result.ParseOk = $true
            $result.Result = Get-NormalizedStatusToken -Value ([string]$json.Result)

            if ($null -ne $json.PSObject.Properties['ExitCode']) {
                $result.ExitCode = [int]$json.ExitCode
            }

            if ($null -ne $json.PSObject.Properties['ExpectedRoundCount']) {
                $result.ExpectedRoundCount = [int]$json.ExpectedRoundCount
            }

            if ($null -ne $json.PSObject.Properties['CompletedRoundCount']) {
                $result.CompletedRoundCount = [int]$json.CompletedRoundCount
            }
        }
        else {
            $lines = @(Get-Content -LiteralPath $StatusPath -Encoding utf8 -ErrorAction Stop)
            $map = @{}
            foreach ($line in $lines) {
                if ($line -match '^([^=]+)=(.*)$') {
                    $map[$Matches[1].Trim().ToLowerInvariant()] = $Matches[2].Trim()
                }
            }

            $result.ParseOk = ($map.Count -gt 0)
            $result.Result = Get-NormalizedStatusToken -Value ([string]$map['result'])

            if ($map.ContainsKey('exit_code')) {
                $parsedExitCode = 0
                if ([int]::TryParse([string]$map['exit_code'], [ref]$parsedExitCode)) {
                    $result.ExitCode = $parsedExitCode
                }
            }

            if ($map.ContainsKey('expected_round_count')) {
                $parsedExpected = 0
                if ([int]::TryParse([string]$map['expected_round_count'], [ref]$parsedExpected)) {
                    $result.ExpectedRoundCount = $parsedExpected
                }
            }

            if ($map.ContainsKey('completed_round_count')) {
                $parsedCompleted = 0
                if ([int]::TryParse([string]$map['completed_round_count'], [ref]$parsedCompleted)) {
                    $result.CompletedRoundCount = $parsedCompleted
                }
            }
        }
    }
    catch {
        $result.Detail = Convert-ToSingleLineText -Text $_.Exception.Message
        return [pscustomobject]$result
    }

    if ($null -ne $result.ExpectedRoundCount -and $null -ne $result.CompletedRoundCount) {
        $result.CountsConsistent = ($result.ExpectedRoundCount -eq $result.CompletedRoundCount)
    }

    $exitCodePass = ($null -eq $result.ExitCode -or [int]$result.ExitCode -eq 0)
    $result.IsPass = ($result.ParseOk -and $result.Result -eq 'PASS' -and $exitCodePass -and [bool]$result.CountsConsistent)

    $detailParts = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace([string]$result.Result)) {
        [void]$detailParts.Add(('result={0}' -f [string]$result.Result))
    }
    if ($null -ne $result.ExitCode) {
        [void]$detailParts.Add(('exit_code={0}' -f [int]$result.ExitCode))
    }
    if ($null -ne $result.ExpectedRoundCount -and $null -ne $result.CompletedRoundCount) {
        [void]$detailParts.Add(('rounds={0}/{1}' -f [int]$result.CompletedRoundCount, [int]$result.ExpectedRoundCount))
        if (-not [bool]$result.CountsConsistent) {
            [void]$detailParts.Add('counts=mismatch')
        }
    }

    $result.Detail = ($detailParts -join ' ')
    return [pscustomobject]$result
}

function Assert-BStartEligibility {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$RepoRoot,
        [string]$ScriptTag,
        [bool]$BRestartModeRequested
    )

    if ($Stage -ne 'B') {
        return [pscustomobject]@{
            GateRequired = $false
            EffectiveRestartMode = $false
            SnapshotStatusPath = ''
            SnapshotDir = ''
            Alignment = $null
            EffectiveAStatus = ''
            UpdatedSettings = $Settings
        }
    }

    $requiresSnapshotGate = if ($Settings.Contains('B_START_REQUIRES_A_PASS_WITH_SNAPSHOT')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.B_START_REQUIRES_A_PASS_WITH_SNAPSHOT) -Default $true
    }
    else {
        $true
    }

    if (-not $requiresSnapshotGate) {
            Write-Host ("[{0}] b_start_gate required=false action=skip" -f $ScriptTag)
        return [pscustomobject]@{
            GateRequired = $false
            EffectiveRestartMode = $false
            SnapshotStatusPath = ''
            SnapshotDir = ''
            Alignment = $null
            EffectiveAStatus = ''
            UpdatedSettings = $Settings
        }
    }

    $aFinalStatus = if ($Settings.Contains('A_FINAL_STATUS')) {
        Get-NormalizedStatusToken -Value ([string]$Settings.A_FINAL_STATUS)
    }
    else {
        ''
    }

    $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) {
        Get-NormalizedStatusToken -Value ([string]$Settings.SESSION_FINAL_STATUS)
    }
    else {
        ''
    }

    $shutdownRequested = if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REQUESTED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REQUESTED) -Default $false
    }
    else {
        $false
    }

    $shutdownReason = if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REASON')) {
        Convert-ToSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REASON)
    }
    else {
        ''
    }

    $aLaunchPid = if ($Settings.Contains('A_LAUNCH_PID')) {
        Get-ParsedPositiveInt -Value ([string]$Settings.A_LAUNCH_PID)
    }
    else {
        0
    }
    $aLaunchAlive = ($aLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $aLaunchPid))

    $snapshotStatusRaw = if ($Settings.Contains('A_SUCCESS_SNAPSHOT_FINAL_STATUS')) {
        [string]$Settings.A_SUCCESS_SNAPSHOT_FINAL_STATUS
    }
    else {
        ''
    }

    $snapshotStatusPath = Resolve-RepoPathAllowMissing -Path $snapshotStatusRaw -RepoRoot $RepoRoot
    $snapshotEvidence = Read-StageFinalStatusEvidence -StatusPath $snapshotStatusPath

    $effectiveAStatus = $aFinalStatus
    $updatedSettings = $Settings
    $aStatusSource = 'config'

    if ($snapshotEvidence.IsPass) {
        $effectiveAStatus = 'PASS'
        if ($aFinalStatus -ne 'PASS') {
            if (-not [string]::IsNullOrWhiteSpace($StartFilePath)) {
                Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{ A_FINAL_STATUS = 'PASS'; A_LAUNCH_PID = '0' }
                $updatedSettings = Read-KeyValueFile -Path $StartFilePath
            }

            $aStatusSource = 'snapshot-reconciled'
            Write-Host ("[{0}] b_start_gate_reconcile applied=true previous_a_status={1} snapshot_status={2} a_launch_pid={3} a_launch_alive={4}" -f
                $ScriptTag,
                $aFinalStatus,
                (Convert-ToSingleLineText -Text $snapshotEvidence.Detail),
                $aLaunchPid,
                [string]$aLaunchAlive)
        }
        else {
            $aStatusSource = 'config+snapshot'
        }
    }

    if ($effectiveAStatus -ne 'PASS') {
        $reasonParts = New-Object 'System.Collections.Generic.List[string]'
        [void]$reasonParts.Add(('a_status={0}' -f $aFinalStatus))
        [void]$reasonParts.Add(('session_status={0}' -f $sessionStatus))
        [void]$reasonParts.Add(('monitor_shutdown_requested={0}' -f ([string]$shutdownRequested).ToLowerInvariant()))
        if (-not [string]::IsNullOrWhiteSpace($shutdownReason)) {
            [void]$reasonParts.Add(('monitor_shutdown_reason={0}' -f $shutdownReason))
        }
        if ($aLaunchPid -gt 0) {
            [void]$reasonParts.Add(('a_launch_pid={0}' -f $aLaunchPid))
            [void]$reasonParts.Add(('a_launch_alive={0}' -f ([string]$aLaunchAlive).ToLowerInvariant()))
        }
        if ([string]::IsNullOrWhiteSpace($snapshotStatusRaw)) {
            [void]$reasonParts.Add('snapshot_status=missing')
        }
        elseif (-not $snapshotEvidence.Exists) {
            [void]$reasonParts.Add(('snapshot_status=missing path={0}' -f $snapshotStatusRaw))
        }
        elseif (-not $snapshotEvidence.ParseOk) {
            [void]$reasonParts.Add(('snapshot_status=parse-failed path={0}' -f (Convert-ToAnchorPath -Path $snapshotStatusPath)))
            if (-not [string]::IsNullOrWhiteSpace([string]$snapshotEvidence.Detail)) {
                [void]$reasonParts.Add(('snapshot_detail={0}' -f [string]$snapshotEvidence.Detail))
            }
        }
        else {
            [void]$reasonParts.Add(('snapshot_status={0}' -f $snapshotEvidence.Detail))
        }

        throw ("[{0}] b_start_gate blocked: A pass snapshot required ({1})" -f $ScriptTag, ($reasonParts -join '; '))
    }

    if ([string]::IsNullOrWhiteSpace($snapshotStatusRaw)) {
        throw ("[{0}] b_start_gate blocked: A_SUCCESS_SNAPSHOT_FINAL_STATUS is empty" -f $ScriptTag)
    }

    if ([string]::IsNullOrWhiteSpace($snapshotStatusPath) -or -not (Test-Path -LiteralPath $snapshotStatusPath)) {
        throw ("[{0}] b_start_gate blocked: snapshot final status not found ({1})" -f $ScriptTag, $snapshotStatusRaw)
    }

    $snapshotDir = Join-Path (Split-Path -Parent $snapshotStatusPath) 'a_success_snapshot'
    if (-not (Test-Path -LiteralPath $snapshotDir)) {
        throw ("[{0}] b_start_gate blocked: snapshot directory missing ({1})" -f $ScriptTag, (Convert-ToAnchorPath -Path $snapshotDir))
    }

    $alignment = Test-BNormalModeSourceAlignedWithSnapshot -RepoRoot $RepoRoot -SnapshotDir $snapshotDir
    $effectiveRestartMode = $false

    if ([bool]$alignment.Match) {
        Write-Host ("[{0}] b_normal_mode_source_guard status=PASS snapshot_files={1} current_files={2}" -f
            $ScriptTag,
            [int]$alignment.SnapshotCount,
            [int]$alignment.CurrentCount)

        if ($BRestartModeRequested) {
            Write-Host ("[{0}] b_restart_mode_request ignored=true reason=auto-mode-selected-normal" -f $ScriptTag)
        }
    }
    else {
        $effectiveRestartMode = $true
        Write-Host ("[{0}] b_mode_auto selected=restart reason=source-mismatch missing={1} extra={2} content_mismatch={3} action=restore-from-a-snapshot" -f
            $ScriptTag,
            [int]$alignment.MissingCount,
            [int]$alignment.ExtraCount,
            [int]$alignment.ContentMismatchCount)

        if ($BRestartModeRequested) {
            Write-Host ("[{0}] b_restart_mode_request requested=true effective=true reason=auto-mode-selected-restart" -f $ScriptTag)
        }
    }

    $modeText = if ($effectiveRestartMode) { 'restart' } else { 'normal' }

    Write-Host ("[{0}] b_start_gate status=PASS a_status={1} snapshot_status={2} snapshot_dir={3} mode={4}" -f
    $ScriptTag,
    ('{0} ({1})' -f $effectiveAStatus, $aStatusSource),
    (Convert-ToAnchorPath -Path $snapshotStatusPath),
    (Convert-ToAnchorPath -Path $snapshotDir),
    $modeText)

    return [pscustomobject]@{
        GateRequired = $true
        EffectiveRestartMode = [bool]$effectiveRestartMode
        SnapshotStatusPath = [string]$snapshotStatusPath
        SnapshotDir = [string]$snapshotDir
        Alignment = $alignment
        EffectiveAStatus = [string]$effectiveAStatus
        UpdatedSettings = $updatedSettings
    }
}

function Get-MonitorTimelinePath {
    param(
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    $timelineRoot = Join-Path $RepoRoot 'out\artifacts\ab_monitor_timeline'
    if (-not (Test-Path -LiteralPath $timelineRoot)) {
        New-Item -ItemType Directory -Path $timelineRoot -Force | Out-Null
    }

    $token = Get-StableStartFileToken -StartFilePath $StartFilePath
    return (Join-Path $timelineRoot ("monitor_timeline_{0}.jsonl" -f $token))
}

function Write-MonitorTimelineEvent {
    param(
        [string]$TimelinePath,
        [string]$EventName,
        [hashtable]$Fields
    )

    if ([string]::IsNullOrWhiteSpace($TimelinePath) -or [string]::IsNullOrWhiteSpace($EventName)) {
        return
    }

    try {
        $payload = [ordered]@{
            timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            event = $EventName
        }

        if ($null -ne $Fields) {
            foreach ($key in $Fields.Keys) {
                $payload[$key] = $Fields[$key]
            }
        }

        $json = ($payload | ConvertTo-Json -Compress -Depth 6)
        Add-Content -LiteralPath $TimelinePath -Encoding utf8 -Value $json
    }
    catch {
        Write-Warning ("[OPEN-AB-STAGE] monitor_timeline_write_failed path={0} detail={1}" -f $TimelinePath, $_.Exception.Message)
    }
}

function Invoke-SessionAnchorUpdateInStartFile {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Anchors
    )

    $settingsMap = Read-KeyValueFile -Path $Path
    $existingNotes = if ($settingsMap.Contains('SESSION_FINAL_NOTES')) { [string]$settingsMap.SESSION_FINAL_NOTES } else { '' }
    $segments = New-Object 'System.Collections.Generic.List[string]'

    foreach ($part in @($existingNotes -split ';')) {
        $segment = [string]$part
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        $trimmed = $segment.Trim()
        if ($trimmed -match '^(run_dir|guard_log|live_status|b_runtime_log)=') {
            continue
        }

        [void]$segments.Add($trimmed)
    }

    foreach ($anchorKey in @('run_dir', 'guard_log', 'live_status', 'b_runtime_log')) {
        if (-not $Anchors.ContainsKey($anchorKey)) {
            continue
        }

        $value = [string]$Anchors[$anchorKey]
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        [void]$segments.Add("$anchorKey=$value")
    }

    $newNotes = ($segments -join '; ')
    Invoke-KeyValueFileValueUpdateCore -Path $Path -Values @{ SESSION_FINAL_NOTES = $newNotes }
    return $newNotes
}

function Test-StageLaunchAllowed {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [System.Collections.IDictionary]$Settings,
        [string]$ScriptTag
    )

    $sameStatusKey = if ($Stage -eq 'A') { 'A_FINAL_STATUS' } else { 'B_FINAL_STATUS' }
    $samePidKey = if ($Stage -eq 'A') { 'A_LAUNCH_PID' } else { 'B_LAUNCH_PID' }
    $peerStage = if ($Stage -eq 'A') { 'B' } else { 'A' }
    $peerStatusKey = if ($Stage -eq 'A') { 'B_FINAL_STATUS' } else { 'A_FINAL_STATUS' }
    $peerPidKey = if ($Stage -eq 'A') { 'B_LAUNCH_PID' } else { 'A_LAUNCH_PID' }

    $samePid = if ($Settings.Contains($samePidKey)) {
        Get-ParsedPositiveInt -Value ([string]$Settings[$samePidKey])
    }
    else {
        0
    }
    if ($samePid -gt 0 -and (Test-ProcessAlive -ProcessId $samePid)) {
        $sameStatus = if ($Settings.Contains($sameStatusKey)) { [string]$Settings[$sameStatusKey] } else { '' }
        $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) { [string]$Settings.SESSION_FINAL_STATUS } else { '' }
        Write-Output ("[{0}] existing_stage_running stage={1} pid={2} stage_status={3} session_status={4} action=skip_launch" -f $ScriptTag, $Stage, $samePid, $sameStatus, $sessionStatus)
        return $false
    }

    $peerPid = if ($Settings.Contains($peerPidKey)) {
        Get-ParsedPositiveInt -Value ([string]$Settings[$peerPidKey])
    }
    else {
        0
    }
    if ($peerPid -gt 0 -and (Test-ProcessAlive -ProcessId $peerPid)) {
        $peerStatus = if ($Settings.Contains($peerStatusKey)) { [string]$Settings[$peerStatusKey] } else { '' }
        $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) { [string]$Settings.SESSION_FINAL_STATUS } else { '' }
        Write-Output ("[{0}] peer_stage_running stage={1} peer_stage={2} peer_pid={3} peer_status={4} session_status={5} action=skip_launch" -f $ScriptTag, $Stage, $peerStage, $peerPid, $peerStatus, $sessionStatus)
        return $false
    }

    return $true
}

function Resolve-CurrentStageRunDir {
    param(
        [datetime]$LaunchTime,
        [System.Collections.IDictionary]$Settings,
        [string]$SessionOutDirRoot,
        [int]$StageProcessId = 0
    )

    $currentRunDir = ''
    for ($attempt = 0; $attempt -lt 24; $attempt++) {
        $candidate = Get-LatestTimestampedDirectory -Root $SessionOutDirRoot -After $LaunchTime
        if ($null -ne $candidate) {
            $currentRunDir = $candidate.FullName
            break
        }

        if ($StageProcessId -gt 0 -and -not (Test-ProcessAlive -ProcessId $StageProcessId)) {
            break
        }

        Start-Sleep -Seconds 5
    }

    if (-not [string]::IsNullOrWhiteSpace($currentRunDir)) {
        return $currentRunDir
    }

    if ($StageProcessId -gt 0 -and -not (Test-ProcessAlive -ProcessId $StageProcessId)) {
        return ''
    }

    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $hintRunDir = Get-LatestAnchorValueFromNoteText -Notes ([string]$Settings.SESSION_FINAL_NOTES) -Key 'run_dir'
        if (-not [string]::IsNullOrWhiteSpace($hintRunDir)) {
            try {
                return (Resolve-RepoPath -Path $hintRunDir)
            }
            catch {
                return ''
            }
        }
    }

    return ''
}

function Add-StageTaskDefinitionFixTicket {
    param(
        [string]$StartFilePath,
        [System.Collections.IDictionary]$Settings,
        [ValidateSet('A', 'B')][string]$Stage,
        [string]$TaskDefinitionRelative,
        [int]$FailCount,
        [int]$MaxFails,
        [int]$PrecheckExitCode,
        [AllowEmptyString()][string]$MainRound = '',
        [int]$FailureOperation = 0,
        [AllowEmptyString()][string]$FailurePhase = '',
        [AllowEmptyString()][string]$FailureEvidence = '',
        [AllowEmptyString()][string]$FailureFingerprint = '',
        [AllowEmptyString()][string]$TaskStartAt = '',
        [bool]$OneTimeRetryOnly = $false,
        [int]$RetryAttempt = 0,
        [int]$RetryMax = 0
    )

    $queuePath = Get-AgentTicketQueuePath -Settings $Settings -RepoRoot $repoRoot
    if ([string]::IsNullOrWhiteSpace($queuePath)) {
        Write-Output '[OPEN-AB-STAGE] task_static_precheck ticket_emit=skip reason=queue-path-empty'
        return
    }

    $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) { [string]$Settings.SESSION_FINAL_STATUS } else { '' }
    $aStatus = if ($Settings.Contains('A_FINAL_STATUS')) { [string]$Settings.A_FINAL_STATUS } else { '' }
    $bStatus = if ($Settings.Contains('B_FINAL_STATUS')) { [string]$Settings.B_FINAL_STATUS } else { '' }
    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'run_dir'

    $operationText = if ($FailureOperation -gt 0) { [string]$FailureOperation } else { 'unknown' }
    $roundText = if ([string]::IsNullOrWhiteSpace($MainRound)) { 'unknown' } else { $MainRound }
    $phaseText = if ([string]::IsNullOrWhiteSpace($FailurePhase)) { 'static-precheck' } else { $FailurePhase }
    $detail = ('stage={0} round={1} op={2} phase={3} category=task-definition-static-precheck fail_count={4} limit={5} exit={6} task_definition={7}' -f $Stage, $roundText, $operationText, $phaseText, $FailCount, $MaxFails, $PrecheckExitCode, $TaskDefinitionRelative)
    if (-not [string]::IsNullOrWhiteSpace($FailureEvidence)) {
        $detail = ('{0} failure={1}' -f $detail, (Convert-ToSingleLineText -Text $FailureEvidence))
    }
    if ($OneTimeRetryOnly) {
        $detail = ('{0} fingerprint_duplicate=true one_time_retry_only=true round={1} phase={2} task_start_at={3} fingerprint={4}' -f $detail, $MainRound, $FailurePhase, $TaskStartAt, $FailureFingerprint)
    }
    elseif ($RetryMax -gt 0) {
        $detail = ('{0} fingerprint_duplicate=true retry_attempt={1} retry_limit={2} round={3} phase={4} task_start_at={5} fingerprint={6}' -f $detail, $RetryAttempt, $RetryMax, $MainRound, $FailurePhase, $TaskStartAt, $FailureFingerprint)
    }
    $focusedCheck = if ($FailureOperation -gt 0 -and $roundText -ne 'unknown') { "-RoundTag $roundText -OperationIndex $FailureOperation" } else { "-RoundTag $roundText" }
    $recommendedAction = "Report root cause first. Fix only the allowed task-definition range, then rerun check_task_definition_static.ps1 $focusedCheck -Policy enforce for the failing op. Resume only after it passes; return handled_at after handling."
    if ($OneTimeRetryOnly) {
        $recommendedAction = 'Fingerprint duplicate detected in code-step. AI has exactly one extra self-heal attempt for this fingerprint; update task-definition first, rerun static precheck immediately, then relaunch. If the same fingerprint repeats again, stop auto-retry and escalate to manual intervention.'
    }
    elseif ($RetryMax -gt 0) {
        $remaining = [Math]::Max(0, $RetryMax - $RetryAttempt)
        $recommendedAction = ('Fingerprint duplicate detected in code-step (same failure point as previous run). Do NOT repeat the same patch style; change repair strategy and make evidence-changing edits (round-level op imprint/taskdef hash/source summary), then rerun static precheck and relaunch. Retry budget {0}/{1}, remaining={2}. If unchanged fingerprint repeats, transfer to manual intervention.' -f $RetryAttempt, $RetryMax, $remaining)
    }
    $ticketId = ('T{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmssfff'), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $ticket = [ordered]@{
        schema = 'AB_AGENT_TICKET_V1'
        ticket_id = $ticketId
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        source = 'open_unattended_ab_stage_window'
        event = 'task-definition-fix-required'
        severity = 'high'
        requires_confirmation = $false
        confirmation_key = ''
        start_file = (Convert-ToAnchorPath -Path $StartFilePath)
        guard_log = ''
        guard_state = ''
        queue_path = (Convert-ToAnchorPath -Path $queuePath)
        session_final_status = (Convert-ToSingleLineText -Text $sessionStatus)
        a_final_status = (Convert-ToSingleLineText -Text $aStatus)
        b_final_status = (Convert-ToSingleLineText -Text $bStatus)
        run_dir = (Convert-ToSingleLineText -Text $runDirAnchor)
        incident_dir = ''
        detail = (Convert-ToBoundedSingleLineText -Text $detail -MaxChars 360)
        recommended_action = (Convert-ToBoundedSingleLineText -Text $recommendedAction -MaxChars 280)
        preferred_stage = $Stage
        main_round = (Convert-ToSingleLineText -Text $MainRound)
        failure_operation = $FailureOperation
        failure_kind = if ($OneTimeRetryOnly -or $RetryMax -gt 0) { 'task-definition-fingerprint-duplicate' } else { 'task-definition-mismatch' }
        failure_category = if ($OneTimeRetryOnly -or $RetryMax -gt 0) { 'task-definition-static-precheck-fingerprint-duplicate' } else { 'task-definition-static-precheck' }
        failure_source = 'tools/test/open_unattended_ab_stage_window.ps1'
        failure_evidence = (Convert-ToBoundedSingleLineText -Text $detail -MaxChars 260)
        self_healable = $true
        non_recoverable_env = $false
        dedup_signature = ('task-definition-static-precheck|{0}|{1}|{2}|{3}|{4}' -f $Stage, $TaskDefinitionRelative, $roundText, $operationText, (Convert-ToSingleLineText -Text $FailureEvidence))
    }

    if ((Test-AgentTicketDedupSignaturePresent -QueuePath $queuePath -DedupSignature ([string]$ticket.dedup_signature)) -or
        (Test-RecentTaskDefinitionFixTicketPresent -QueuePath $queuePath -Stage $Stage -Round $roundText -TaskDefinition $TaskDefinitionRelative -WindowMinutes 40)) {
        Write-Output ('[OPEN-AB-STAGE] task_static_precheck ticket_emit=suppressed reason=duplicate-failure stage={0} round={1} op={2}' -f $Stage, $roundText, $operationText)
        return
    }

    $line = $ticket | ConvertTo-Json -Compress -Depth 8
    if (Write-JsonLineWithRetry -Path $queuePath -Line $line) {
        Write-Output ('[OPEN-AB-STAGE] task_static_precheck ticket_emit=queued id={0} queue={1} fail_count={2} limit={3}' -f $ticketId, (Convert-ToAnchorPath -Path $queuePath), $FailCount, $MaxFails)
        return
    }

    Write-Output ('[OPEN-AB-STAGE] task_static_precheck ticket_emit=failed queue={0} fail_count={1} limit={2}' -f (Convert-ToAnchorPath -Path $queuePath), $FailCount, $MaxFails)
}

function Test-AgentTicketDedupSignaturePresent {
    param(
        [string]$QueuePath,
        [string]$DedupSignature
    )

    if ([string]::IsNullOrWhiteSpace($QueuePath) -or [string]::IsNullOrWhiteSpace($DedupSignature) -or -not (Test-Path -LiteralPath $QueuePath)) {
        return $false
    }

    foreach ($line in @(Get-Content -LiteralPath $QueuePath -Tail 500 -Encoding utf8 -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
        try {
            $existingTicket = ([string]$line) | ConvertFrom-Json -ErrorAction Stop
            if ([string]$existingTicket.dedup_signature -eq $DedupSignature) {
                return $true
            }
        }
        catch { $null = $_ }
    }

    return $false
}

function Test-RecentTaskDefinitionFixTicketPresent {
    param(
        [string]$QueuePath,
        [string]$Stage,
        [string]$Round,
        [string]$TaskDefinition,
        [int]$WindowMinutes = 40
    )

    if ([string]::IsNullOrWhiteSpace($QueuePath) -or -not (Test-Path -LiteralPath $QueuePath)) {
        return $false
    }

    $cutoff = (Get-Date).AddMinutes(-1 * $WindowMinutes)
    foreach ($line in @(Get-Content -LiteralPath $QueuePath -Tail 500 -Encoding utf8 -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
        try {
            $ticket = ([string]$line) | ConvertFrom-Json -ErrorAction Stop
            if ([string]$ticket.event -ne 'task-definition-fix-required') { continue }
            $createdAt = [datetime]::MinValue
            if (-not [datetime]::TryParse([string]$ticket.created_at, [ref]$createdAt) -or $createdAt -lt $cutoff) { continue }
            if ([string]$ticket.preferred_stage -ne $Stage) { continue }
            if ($Round -ne 'unknown' -and [string]$ticket.main_round -ne $Round) { continue }
            $existingDetail = Convert-ToSingleLineText -Text ([string]$ticket.detail)
            if (-not $existingDetail.Contains("task_definition=$TaskDefinition")) { continue }
            return $true
        }
        catch { $null = $_ }
    }

    return $false
}

function Get-TaskStaticFailureLocation {
    param(
        [string[]]$Lines,
        [string]$FallbackRound
    )

    $result = [ordered]@{ Round = $FallbackRound; Operation = 0; Evidence = '' }
    foreach ($line in @($Lines)) {
        $text = Convert-ToSingleLineText -Text ([string]$line)
        if ($text -notmatch '^\[TASK-STATIC-CHECK\] severity=(?:error|warn) detail=(.+)$') { continue }
        $result.Evidence = $Matches[1]
        if ($result.Evidence -match '(?:^|\s)round=(D[1-4])(?:\s|$)') {
            $result.Round = $Matches[1].ToUpperInvariant()
        }
        if ($result.Evidence -match '(?:^|\s)op=(\d+)(?:\s|$)') {
            $result.Operation = [int]$Matches[1]
        }
    }

    return [pscustomobject]$result
}

function Get-TaskDefinitionRepairEvidence {
    param(
        [string]$TaskDefinitionPath,
        [string]$Round
    )

    $result = [ordered]@{ FileHash = ''; RoundImprintHash = '' }
    $resolvedPath = if ([System.IO.Path]::IsPathRooted($TaskDefinitionPath)) { $TaskDefinitionPath } else { Join-Path $repoRoot $TaskDefinitionPath }
    if (-not (Test-Path -LiteralPath $resolvedPath)) { return [pscustomobject]$result }

    $result.FileHash = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA1).Hash.ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($Round)) { return [pscustomobject]$result }

    try {
        $taskObject = Get-Content -LiteralPath $resolvedPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $taskObject.rounds.PSObject.Properties[$Round]) { return [pscustomobject]$result }
        $roundNode = $taskObject.rounds.PSObject.Properties[$Round].Value
        if ($null -eq $roundNode.PSObject.Properties['operations']) { return [pscustomobject]$result }
        $roundJson = $roundNode.operations | ConvertTo-Json -Depth 32 -Compress
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            $roundBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$roundJson)
            $result.RoundImprintHash = ([System.BitConverter]::ToString($sha1.ComputeHash($roundBytes))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha1.Dispose()
        }
    }
    catch { $null = $_ }

    return [pscustomobject]$result
}

function Add-StageTaskDefinitionBlockedTicket {
    param(
        [string]$StartFilePath,
        [System.Collections.IDictionary]$Settings,
        [ValidateSet('A', 'B')][string]$Stage,
        [string]$TaskDefinitionRelative,
        [int]$FailCount,
        [int]$MaxFails,
        [int]$PrecheckExitCode,
        [string]$BlockEvent,
        [AllowEmptyString()][string]$MainRound = '',
        [int]$FailureOperation = 0,
        [AllowEmptyString()][string]$FailurePhase = 'static-precheck',
        [AllowEmptyString()][string]$FailureEvidence = '',
        [AllowEmptyString()][string]$ExtraDetail = '',
        [AllowEmptyString()][string]$RecommendedActionOverride = '',
        [AllowEmptyString()][string]$FailureCategoryOverride = '',
        [AllowEmptyString()][string]$FailureKindOverride = ''
    )

    $queuePath = Get-AgentTicketQueuePath -Settings $Settings -RepoRoot $repoRoot
    if ([string]::IsNullOrWhiteSpace($queuePath)) {
        Write-Output '[OPEN-AB-STAGE] task_static_precheck block_ticket_emit=skip reason=queue-path-empty'
        return
    }

    $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) { [string]$Settings.SESSION_FINAL_STATUS } else { '' }
    $aStatus = if ($Settings.Contains('A_FINAL_STATUS')) { [string]$Settings.A_FINAL_STATUS } else { '' }
    $bStatus = if ($Settings.Contains('B_FINAL_STATUS')) { [string]$Settings.B_FINAL_STATUS } else { '' }
    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'run_dir'

    $eventName = 'manual-wait-paused'
    $requiresConfirmation = $true
    $confirmationKey = 'LOCAL_GUARD_RESTART_APPROVED'
    $selfHealable = $false
    $failureCategory = 'task-definition-static-precheck-blocked'
    $detailCategory = 'task-definition-static-precheck-blocked'
    $recommendedAction = 'Report root cause and remediation path first. Task-definition static precheck has exceeded the allowed retry limit, so do not continue automatic stage restarts. Review the task-definition file under testdata, decide whether to repair or reset baseline, rerun task static precheck manually, and only then resume the guarded workflow. After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'

    switch ((Convert-ToSingleLineText -Text $BlockEvent).ToLowerInvariant()) {
        'recovery-await-confirmation' {
            $eventName = 'recovery-await-confirmation'
            $recommendedAction = 'Report root cause and remediation path first. Task-definition static precheck has exceeded the allowed retry limit, so pause automatic retries and require explicit restart approval after evidence review. Repair or reset the task-definition file under testdata, rerun task static precheck manually, and only then resume the guarded workflow. After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'
        }
        'task-definition-fix-required' {
            $eventName = 'task-definition-fix-required'
            $requiresConfirmation = $false
            $confirmationKey = ''
            $selfHealable = $true
            $recommendedAction = 'Report root cause and remediation path first. Task-definition static precheck has exceeded the allowed retry limit, so do not restart automatically; instead repair the task-definition file under testdata until static precheck passes, then resume via the standard business_resume path. After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($RecommendedActionOverride)) {
        $recommendedAction = Convert-ToSingleLineText -Text $RecommendedActionOverride
    }
    if (-not [string]::IsNullOrWhiteSpace($FailureCategoryOverride)) {
        $failureCategory = Convert-ToSingleLineText -Text $FailureCategoryOverride
    }

    $failureKind = 'task-definition-mismatch'
    if (-not [string]::IsNullOrWhiteSpace($FailureKindOverride)) {
        $failureKind = Convert-ToSingleLineText -Text $FailureKindOverride
    }

    $operationText = if ($FailureOperation -gt 0) { [string]$FailureOperation } else { 'unknown' }
    $roundText = if ([string]::IsNullOrWhiteSpace($MainRound)) { 'unknown' } else { $MainRound }
    $phaseText = if ([string]::IsNullOrWhiteSpace($FailurePhase)) { 'static-precheck' } else { $FailurePhase }
    $detail = ('stage={0} round={1} op={2} phase={3} category={4} fail_count={5} limit={6} exit={7} task_definition={8}' -f $Stage, $roundText, $operationText, $phaseText, $detailCategory, $FailCount, $MaxFails, $PrecheckExitCode, $TaskDefinitionRelative)
    if (-not [string]::IsNullOrWhiteSpace($FailureEvidence)) {
        $detail = ('{0} failure={1}' -f $detail, (Convert-ToSingleLineText -Text $FailureEvidence))
    }
    if (-not [string]::IsNullOrWhiteSpace($ExtraDetail)) {
        $detail = ('{0} {1}' -f $detail, (Convert-ToSingleLineText -Text $ExtraDetail))
    }
    $ticketId = ('T{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmssfff'), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $ticket = [ordered]@{
        schema = 'AB_AGENT_TICKET_V1'
        ticket_id = $ticketId
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        source = 'open_unattended_ab_stage_window'
        event = $eventName
        severity = 'high'
        requires_confirmation = $requiresConfirmation
        confirmation_key = $confirmationKey
        start_file = (Convert-ToAnchorPath -Path $StartFilePath)
        guard_log = ''
        guard_state = ''
        queue_path = (Convert-ToAnchorPath -Path $queuePath)
        session_final_status = (Convert-ToSingleLineText -Text $sessionStatus)
        a_final_status = (Convert-ToSingleLineText -Text $aStatus)
        b_final_status = (Convert-ToSingleLineText -Text $bStatus)
        run_dir = (Convert-ToSingleLineText -Text $runDirAnchor)
        incident_dir = ''
        detail = (Convert-ToBoundedSingleLineText -Text $detail -MaxChars 360)
        recommended_action = (Convert-ToBoundedSingleLineText -Text $recommendedAction -MaxChars 280)
        preferred_stage = $Stage
        main_round = (Convert-ToSingleLineText -Text $MainRound)
        failure_operation = $FailureOperation
        failure_kind = $failureKind
        failure_category = $failureCategory
        failure_source = 'tools/test/open_unattended_ab_stage_window.ps1'
        failure_evidence = (Convert-ToBoundedSingleLineText -Text $detail -MaxChars 260)
        self_healable = $selfHealable
        non_recoverable_env = $false
        dedup_signature = ('task-definition-static-precheck-blocked|{0}|{1}|{2}|{3}|{4}|{5}' -f $eventName, $Stage, $TaskDefinitionRelative, $FailCount, $MaxFails, (Convert-ToSingleLineText -Text $failureCategory))
    }

    $line = $ticket | ConvertTo-Json -Compress -Depth 8
    if (Write-JsonLineWithRetry -Path $queuePath -Line $line) {
        Write-Output ('[OPEN-AB-STAGE] task_static_precheck block_ticket_emit=queued id={0} queue={1} fail_count={2} limit={3}' -f $ticketId, (Convert-ToAnchorPath -Path $queuePath), $FailCount, $MaxFails)
        return
    }

    Write-Output ('[OPEN-AB-STAGE] task_static_precheck block_ticket_emit=failed queue={0} fail_count={1} limit={2}' -f (Convert-ToAnchorPath -Path $queuePath), $FailCount, $MaxFails)
}

function Assert-PrecheckGateReady {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$ScriptTag
    )

    if ($null -eq $Settings) {
        throw "[$ScriptTag] start file settings map is null"
    }

    $precheckRequired = if ($Settings.Contains('PRECHECK_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.PRECHECK_REQUIRED) -Default $true
    }
    else {
        $true
    }

    if (-not $precheckRequired) {
        Write-Output ("[{0}] precheck_gate required=false action=skip" -f $ScriptTag)
        return
    }

    $statusRaw = if ($Settings.Contains('PRECHECK_STATUS')) { [string]$Settings.PRECHECK_STATUS } else { '' }
    $startGateRaw = if ($Settings.Contains('PRECHECK_START_GATE')) { [string]$Settings.PRECHECK_START_GATE } else { '' }
    $remoteLockRaw = if ($Settings.Contains('PRECHECK_REMOTE_LOCK')) { [string]$Settings.PRECHECK_REMOTE_LOCK } else { '' }

    $status = $statusRaw.Trim().ToUpperInvariant()
    $startGate = $startGateRaw.Trim().ToUpperInvariant()
    $remoteLock = $remoteLockRaw.Trim().ToUpperInvariant()
    $allowedRemoteLockStates = @('ABSENT', 'HELD-BY-SELF')

    $reasons = New-Object 'System.Collections.Generic.List[string]'
    if ($status -ne 'PASS') {
        [void]$reasons.Add(("PRECHECK_STATUS={0}" -f $statusRaw))
    }
    if ($startGate -ne 'READY') {
        [void]$reasons.Add(("PRECHECK_START_GATE={0}" -f $startGateRaw))
    }
    if (-not ($allowedRemoteLockStates -contains $remoteLock)) {
        [void]$reasons.Add(("PRECHECK_REMOTE_LOCK={0}" -f $remoteLockRaw))
    }

    if ($reasons.Count -gt 0) {
        $reasonText = ($reasons -join '; ')
        Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reasonText
            PRECHECK_FAILURE_REASON = $reasonText
        }
        throw ("[{0}] precheck gate blocked: {1}" -f $ScriptTag, $reasonText)
    }

    Write-Output ("[{0}] precheck_gate status=PASS gate=READY remote_lock={1}" -f $ScriptTag, $remoteLockRaw)
}

function Invoke-LaunchReadyGate {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$ScriptTag,
        [string]$RepoRoot
    )

    if ($null -eq $Settings) {
        throw "[$ScriptTag] start file settings map is null for launch-ready gate"
    }

    $launchReadyGateEnabled = if ($Settings.Contains('LAUNCH_READY_GATE_ENABLED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.LAUNCH_READY_GATE_ENABLED) -Default $true
    }
    else {
        $true
    }

    if (-not $launchReadyGateEnabled) {
        Write-Output ("[{0}] launch_ready_gate enabled=false action=skip" -f $ScriptTag)
        return
    }

    $launchReadyScript = Join-Path $RepoRoot 'tools\test\check_unattended_ab_launch_ready.ps1'
    if (-not (Test-Path -LiteralPath $launchReadyScript)) {
        throw "[$ScriptTag] launch-ready gate script not found: $launchReadyScript"
    }

    $launchReadyDetailedOutput = if ($Settings.Contains('LAUNCH_READY_GATE_DETAILED_OUTPUT')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.LAUNCH_READY_GATE_DETAILED_OUTPUT) -Default $false
    }
    else {
        $false
    }

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    $launchReadyArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $launchReadyScript,
        '-StartFile', $StartFilePath,
        '-Stage', $Stage,
        '-GuardManagedLaunch'
    )
    if ($launchReadyDetailedOutput) {
        $launchReadyArgs += '-DetailedOutput'
    }

    Write-Output ("[{0}] launch_ready_gate status=START stage={1} start_file={2} detailed_output={3}" -f $ScriptTag, $Stage, (Convert-ToAnchorPath -Path $StartFilePath), [string]$launchReadyDetailedOutput)

    $outputLines = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = 1
    try {
        & $powershellPath @launchReadyArgs 2>&1 | ForEach-Object {
            $line = [string]$_
            [void]$outputLines.Add($line)
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-Output $line
            }
        }
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $exitCode = 1
        $fallbackLine = [string]$_.Exception.Message
        [void]$outputLines.Add($fallbackLine)
        if (-not [string]::IsNullOrWhiteSpace($fallbackLine)) {
            Write-Output $fallbackLine
        }
    }

    $outputLines = @($outputLines)

    $resultMarker = @($outputLines | Where-Object {
        $text = (Convert-ToSingleLineText -Text ([string]$_)).Trim()
        $text.StartsWith('AB_LAUNCH_READY_RESULT=', [System.StringComparison]::OrdinalIgnoreCase) -or $text -match '^\[AB-LAUNCH-READY\]\s+result=(pass|fail)$'
    } | Select-Object -Last 1)
    $resultValue = ''
    if ($resultMarker.Count -gt 0) {
        $resultText = (Convert-ToSingleLineText -Text ([string]$resultMarker[0])).Trim()
        if ($resultText.StartsWith('AB_LAUNCH_READY_RESULT=', [System.StringComparison]::OrdinalIgnoreCase)) {
            $resultValue = $resultText.Replace('AB_LAUNCH_READY_RESULT=', '').Trim().ToUpperInvariant()
        }
        elseif ($resultText -match '^\[AB-LAUNCH-READY\]\s+result=(pass|fail)$') {
            $resultValue = ([string]$Matches[1]).Trim().ToUpperInvariant()
        }
    }

    if ($exitCode -ne 0 -or $resultValue -ne 'PASS') {
        $reason = "LAUNCH_READY_GATE_FAIL exit=$exitCode result=$resultValue"
        Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reason
            PRECHECK_FAILURE_REASON = $reason
        }
        throw ("[{0}] launch-ready gate blocked: {1}" -f $ScriptTag, $reason)
    }

    Write-Output ("[{0}] launch_ready_gate status=PASS stage={1} result={2}" -f $ScriptTag, $Stage, $resultValue)
}

function Assert-NetworkPrecheckReady {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$ScriptTag,
        [string]$RepoRoot
    )

    if ($null -eq $Settings) {
        throw "[$ScriptTag] start file settings map is null for network precheck"
    }

    $networkPrecheckRequired = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRED) -Default $true
    }
    else {
        $true
    }

    if (-not $networkPrecheckRequired) {
        Write-Output ("[{0}] network_precheck required=false action=skip" -f $ScriptTag)
        return
    }

    $checkLocal = if ($Settings.Contains('NETWORK_PRECHECK_LOCAL_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_LOCAL_REQUIRED) -Default $true
    }
    else {
        $true
    }

    $checkRemote = if ($Settings.Contains('NETWORK_PRECHECK_REMOTE_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REMOTE_REQUIRED) -Default $true
    }
    else {
        $true
    }

    $checkIPv4 = if ($Settings.Contains('NETWORK_PRECHECK_CHECK_IPV4')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_CHECK_IPV4) -Default $true
    }
    else {
        $true
    }

    $checkIPv6 = if ($Settings.Contains('NETWORK_PRECHECK_CHECK_IPV6')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_CHECK_IPV6) -Default $true
    }
    else {
        $true
    }

    $requireIPv4 = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRE_IPV4')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRE_IPV4) -Default $false
    }
    else {
        $false
    }

    $requireIPv6 = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRE_IPV6')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRE_IPV6) -Default $true
    }
    else {
        $true
    }

    if (-not $checkLocal -and -not $checkRemote) {
        throw "[$ScriptTag] network precheck misconfigured: both local and remote checks are disabled"
    }

    if (-not $checkIPv4 -and -not $checkIPv6) {
        throw "[$ScriptTag] network precheck misconfigured: both IPv4 and IPv6 checks are disabled"
    }

    if ($requireIPv4 -and -not $checkIPv4) {
        $checkIPv4 = $true
    }
    if ($requireIPv6 -and -not $checkIPv6) {
        $checkIPv6 = $true
    }

    $targets = if ($Settings.Contains('NETWORK_PRECHECK_TARGETS') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.NETWORK_PRECHECK_TARGETS)) {
        [string]$Settings.NETWORK_PRECHECK_TARGETS
    }
    else {
        'whois.iana.org;whois.arin.net'
    }

    $timeoutSec = 8
    if ($Settings.Contains('NETWORK_PRECHECK_TIMEOUT_SEC')) {
        $parsedTimeout = 0
        if ([int]::TryParse(([string]$Settings.NETWORK_PRECHECK_TIMEOUT_SEC), [ref]$parsedTimeout)) {
            if ($parsedTimeout -ge 1 -and $parsedTimeout -le 30) {
                $timeoutSec = $parsedTimeout
            }
        }
    }

    $remoteIp = if ($Settings.Contains('REMOTE_IP') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_IP)) {
        [string]$Settings.REMOTE_IP
    }
    else {
        '10.0.0.199'
    }

    $remoteUser = if ($Settings.Contains('REMOTE_USER') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_USER)) {
        [string]$Settings.REMOTE_USER
    }
    else {
        'larson'
    }

    $remoteKeyRaw = if ($Settings.Contains('REMOTE_KEYPATH') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_KEYPATH)) {
        [string]$Settings.REMOTE_KEYPATH
    }
    else {
        "/c/Users/$env:USERNAME/.ssh/id_rsa"
    }

    $precheckScript = Join-Path $RepoRoot 'tools\dev\check_dualstack_whois_connectivity.ps1'
    if (-not (Test-Path -LiteralPath $precheckScript)) {
        throw "[$ScriptTag] network precheck script not found: $precheckScript"
    }

    $resolvedKeyPath = ''
    if ($checkRemote) {
        $resolvedKeyPath = Resolve-RemoteKeyPath -InputPath $remoteKeyRaw -Purpose 'SSH private key for network precheck'
    }

    $outputLines = @()
    $exitCode = 1
    try {
        $outputLines = @((& $precheckScript `
            -Targets $targets `
            -TimeoutSec $timeoutSec `
            -CheckLocal:$checkLocal `
            -CheckRemote:$checkRemote `
            -CheckIPv4:$checkIPv4 `
            -CheckIPv6:$checkIPv6 `
            -RequireIPv4:$requireIPv4 `
            -RequireIPv6:$requireIPv6 `
            -RemoteIp $remoteIp `
            -RemoteUser $remoteUser `
            -KeyPath $resolvedKeyPath 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $exitCode = 1
        $outputLines = @($_.Exception.Message)
    }

    foreach ($line in @($outputLines)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    $nowText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    if ($exitCode -ne 0) {
        $reason = "NETWORK_PRECHECK_FAIL exit=$exitCode targets=$targets local=$checkLocal remote=$checkRemote check_ipv4=$checkIPv4 check_ipv6=$checkIPv6 require_ipv4=$requireIPv4 require_ipv6=$requireIPv6"
        Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reason
            PRECHECK_FAILURE_REASON = $reason
            NETWORK_PRECHECK_LAST_RESULT = 'FAIL'
            NETWORK_PRECHECK_LAST_AT = $nowText
            NETWORK_PRECHECK_LAST_REASON = $reason
        }
        throw ("[{0}] network precheck blocked: {1}" -f $ScriptTag, $reason)
    }

    Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{
        NETWORK_PRECHECK_LAST_RESULT = 'PASS'
        NETWORK_PRECHECK_LAST_AT = $nowText
        NETWORK_PRECHECK_LAST_REASON = ''
    }
    Write-Output ("[{0}] network_precheck status=PASS targets={1} local={2} remote={3} check_ipv4={4} check_ipv6={5} require_ipv4={6} require_ipv6={7}" -f $ScriptTag, $targets, $checkLocal, $checkRemote, $checkIPv4, $checkIPv6, $requireIPv4, $requireIPv6)
}

function Invoke-EnvFromSetting {
    param(
        [string]$EnvName,
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings -or -not $Settings.Contains($Key)) {
        return
    }

    $value = [string]$Settings[$Key]
    if ([string]::IsNullOrWhiteSpace($value)) {
        return
    }

    Set-Item -Path ("Env:{0}" -f $EnvName) -Value $value
}

function Stop-MonitorProcessGracefully {
    param([int[]]$ProcessIds)

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($targetPid in @($ProcessIds | Sort-Object -Unique)) {
        if ($targetPid -le 0) {
            continue
        }

        # Graceful shutdown via WM_CLOSE (avoids exit code -1 dialog)
        # taskkill without /F sends CTRL_CLOSE to console, PowerShell exits as 0
        $null = & 'taskkill.exe' '/PID', ([string]$targetPid) 2>&1
        Start-Sleep -Milliseconds 1500

        if ($null -ne (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
            # Fallback: force kill if still alive
            Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
        }

        [void]$stopped.Add($targetPid)
    }

    return @($stopped)
}

function Invoke-MonitorProcessStopForStartFile {
    param([string]$StartFilePath)

    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $repoRoot
    if ([string]::IsNullOrWhiteSpace($startFileIdentity)) {
        return @()
    }

    $targetPids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if ($line -notmatch 'unattended_ab_session_guard\.ps1|unattended_ab_takeover_trigger\.ps1') {
                    return $false
                }

                $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine $commandLine -RepoRoot $repoRoot
                if ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
                    return $false
                }

                return ($processStartFileIdentity -eq $startFileIdentity)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    foreach ($targetPid in $targetPids) {
        [void](Stop-MonitorProcessGracefully -ProcessIds @($targetPid))
    }

    return @($targetPids)
}

function Invoke-MonitorRoleProcessStopForStartFile {
    param(
        [string]$ScriptLeaf,
        [string]$StartFilePath
    )

    if ([string]::IsNullOrWhiteSpace($ScriptLeaf)) {
        return @()
    }

    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $repoRoot
    if ([string]::IsNullOrWhiteSpace($startFileIdentity)) {
        return @()
    }

    $scriptNeedle = $ScriptLeaf.Trim().ToLowerInvariant()
    $targetPids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if (-not $line.Contains($scriptNeedle)) {
                    return $false
                }

                $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine $commandLine -RepoRoot $repoRoot
                if ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
                    return $false
                }

                return ($processStartFileIdentity -eq $startFileIdentity)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    foreach ($targetPid in $targetPids) {
        [void](Stop-MonitorProcessGracefully -ProcessIds @($targetPid))
    }

    return @($targetPids)
}

function Get-MonitorBindingState {
    param(
        [string]$ScriptLeaf,
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    $scriptNeedle = $ScriptLeaf.Trim().ToLowerInvariant()
    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $RepoRoot
    $matchPids = New-Object 'System.Collections.Generic.List[int]'
    $mismatchPids = New-Object 'System.Collections.Generic.List[int]'
    $unboundPids = New-Object 'System.Collections.Generic.List[int]'

    $candidates = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                return $commandLine.ToLowerInvariant().Contains($scriptNeedle)
            } |
            Select-Object ProcessId, CommandLine
    )

    foreach ($proc in $candidates) {
        $processId = [int]$proc.ProcessId
        $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine ([string]$proc.CommandLine) -RepoRoot $RepoRoot

        if ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
            [void]$unboundPids.Add($processId)
            continue
        }

        if ($processStartFileIdentity -eq $startFileIdentity) {
            [void]$matchPids.Add($processId)
        }
        else {
            [void]$mismatchPids.Add($processId)
        }
    }

    return [pscustomobject]@{
        ScriptLeaf = $ScriptLeaf
        RunningForStartFile = ($matchPids.Count -gt 0)
        MatchCount = [int]$matchPids.Count
        MismatchCount = [int]$mismatchPids.Count
        UnboundCount = [int]$unboundPids.Count
        TotalCount = [int]($matchPids.Count + $mismatchPids.Count + $unboundPids.Count)
        MatchPids = @($matchPids)
        MismatchPids = @($mismatchPids)
        UnboundPids = @($unboundPids)
    }
}

function Get-ParentMonitorBindingEvidence {
    param(
        [string]$ScriptLeaf,
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    $result = [ordered]@{
        Matches = $false
        ProcessId = 0
    }

    try {
        $currentProcess = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
        $parentProcessId = [int]$currentProcess.ParentProcessId
        if ($parentProcessId -le 0) {
            return [pscustomobject]$result
        }

        $parentProcess = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $parentProcessId) -ErrorAction Stop
        $commandLine = [string]$parentProcess.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine) -or -not $commandLine.ToLowerInvariant().Contains($ScriptLeaf.ToLowerInvariant())) {
            return [pscustomobject]$result
        }

        $expectedStartFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $RepoRoot
        $parentStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine $commandLine -RepoRoot $RepoRoot
        if (-not [string]::IsNullOrWhiteSpace($expectedStartFileIdentity) -and $parentStartFileIdentity -eq $expectedStartFileIdentity) {
            $result.Matches = $true
            $result.ProcessId = $parentProcessId
        }
    }
    catch {
        # Parent-process evidence is an optional continuity hint; normal monitor discovery remains authoritative.
    }

    return [pscustomobject]$result
}

function Test-MonitorReuseActivity {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$RepoRoot,
        [int]$MaxStaleMinutes = 5
    )

    $thresholdMinutes = if ($MaxStaleMinutes -gt 0) { $MaxStaleMinutes } else { 5 }
    $now = Get-Date
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $fresh = $false

    foreach ($anchorKey in @('guard_log', 'live_status')) {
        $anchorValue = Get-AnchorValueFromConfig -Settings $Settings -Key $anchorKey
        if ([string]::IsNullOrWhiteSpace($anchorValue)) {
            continue
        }

        $resolvedPath = Resolve-RepoPathAllowMissing -Path $anchorValue -RepoRoot $RepoRoot
        if ([string]::IsNullOrWhiteSpace($resolvedPath) -or -not (Test-Path -LiteralPath $resolvedPath)) {
            [void]$evidence.Add(($anchorKey + ':missing'))
            continue
        }

        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            [void]$evidence.Add(($anchorKey + ':missing'))
            continue
        }

        $ageMinutes = [math]::Round((New-TimeSpan -Start $item.LastWriteTime -End $now).TotalMinutes, 2)
        if ($ageMinutes -le $thresholdMinutes) {
            $fresh = $true
        }

        [void]$evidence.Add(($anchorKey + ':age_min=' + $ageMinutes))
    }

    if ($evidence.Count -eq 0) {
        [void]$evidence.Add('no-anchor-evidence')
    }

    return [pscustomobject]@{
        Active = [bool]$fresh
        ThresholdMinutes = [int]$thresholdMinutes
        Evidence = @($evidence)
    }
}

function Test-MonitorReuseProcessPresence {
    param(
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $RepoRoot
    if ([string]::IsNullOrWhiteSpace($startFileIdentity)) {
        return [pscustomobject]@{
            Active = $false
            MatchCount = 0
            Evidence = @('start-file-identity-unavailable')
        }
    }

    $roles = @('unattended_ab_session_guard.ps1', 'unattended_ab_takeover_trigger.ps1')
    $matchCount = 0
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    foreach ($scriptLeaf in $roles) {
        $state = Get-MonitorBindingState -ScriptLeaf $scriptLeaf -StartFilePath $StartFilePath -RepoRoot $RepoRoot
        if ($null -ne $state -and [bool]$state.RunningForStartFile) {
            $matchCount++
            [void]$evidence.Add(('{0}:match={1}' -f $scriptLeaf, [int]$state.MatchCount))
        }
    }

    if ($evidence.Count -eq 0) {
        [void]$evidence.Add('no-live-process-match')
    }

    return [pscustomobject]@{
        Active = [bool]($matchCount -gt 0)
        MatchCount = [int]$matchCount
        Evidence = @($evidence)
    }
}

function Get-MonitorReuseStaleMinutes {
    param([System.Collections.IDictionary]$Settings)

    $threshold = 15
    if ($null -ne $Settings) {
        foreach ($key in @('LOCAL_GUARD_MONITOR_REUSE_STALE_MINUTES', 'MONITOR_REUSE_MAX_STALE_MINUTES')) {
            if ($Settings.Contains($key)) {
                $candidate = Get-ParsedPositiveInt -Value ([string]$Settings[$key])
                if ($candidate -gt 0) {
                    $threshold = $candidate
                    break
                }
            }
        }
    }

    if ($threshold -lt 1) {
        $threshold = 1
    }
    if ($threshold -gt 120) {
        $threshold = 120
    }

    return [int]$threshold
}

function Test-MonitorRoleReuseActivity {
    param(
        [ValidateSet('guard', 'trigger')][string]$Role,
        [System.Collections.IDictionary]$Settings,
        [string]$RepoRoot,
        [string]$StartFilePath,
        [int]$MaxStaleMinutes = 15
    )

    $thresholdMinutes = if ($MaxStaleMinutes -gt 0) { $MaxStaleMinutes } else { 15 }
    $now = Get-Date
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $fresh = $false

    $anchorKeys = @()
    switch ($Role) {
        'guard' { $anchorKeys = @('guard_log') }
        'trigger' { $anchorKeys = @() }
    }

    foreach ($anchorKey in $anchorKeys) {
        $anchorValue = Get-AnchorValueFromConfig -Settings $Settings -Key $anchorKey
        if ([string]::IsNullOrWhiteSpace($anchorValue)) {
            continue
        }

        $resolvedPath = Resolve-RepoPathAllowMissing -Path $anchorValue -RepoRoot $RepoRoot
        if ([string]::IsNullOrWhiteSpace($resolvedPath) -or -not (Test-Path -LiteralPath $resolvedPath)) {
            [void]$evidence.Add(($anchorKey + ':missing'))
            continue
        }

        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            [void]$evidence.Add(($anchorKey + ':missing'))
            continue
        }

        $ageMinutes = [math]::Round((New-TimeSpan -Start $item.LastWriteTime -End $now).TotalMinutes, 2)
        if ($ageMinutes -le $thresholdMinutes) {
            $fresh = $true
        }

        [void]$evidence.Add(($anchorKey + ':age_min=' + $ageMinutes))
    }

    if ($Role -eq 'trigger') {
        $queueRoot = Join-Path $RepoRoot 'out\artifacts\ab_agent_queue'
        $token = Get-StableStartFileToken -StartFilePath $StartFilePath
        $legacyToken = Get-LegacyStartFileToken -StartFilePath $StartFilePath
        $triggerLogPath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $token)) -LegacyPath (Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $legacyToken))
        $triggerStatePath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $token)) -LegacyPath (Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $legacyToken))
        foreach ($itemPath in @($triggerLogPath, $triggerStatePath)) {
            $label = [System.IO.Path]::GetFileName($itemPath)
            if (-not (Test-Path -LiteralPath $itemPath)) {
                [void]$evidence.Add(($label + ':missing'))
                continue
            }

            $item = Get-Item -LiteralPath $itemPath -ErrorAction SilentlyContinue
            if ($null -eq $item) {
                [void]$evidence.Add(($label + ':missing'))
                continue
            }

            $ageMinutes = [math]::Round((New-TimeSpan -Start $item.LastWriteTime -End $now).TotalMinutes, 2)
            if ($ageMinutes -le $thresholdMinutes) {
                $fresh = $true
            }

            [void]$evidence.Add(($label + ':age_min=' + $ageMinutes))
        }
    }

    if ($evidence.Count -eq 0) {
        [void]$evidence.Add('no-role-evidence')
    }

    return [pscustomobject]@{
        Role = $Role
        Active = [bool]$fresh
        ThresholdMinutes = [int]$thresholdMinutes
        Evidence = @($evidence)
    }
}

function Invoke-PreV1EncodingFixGates {
    param(
        [string]$RepoRoot,
        [string]$ScriptTag
    )

    $gateSpecs = @(
        [pscustomobject]@{
            Name = 'changed'
            ScriptPath = Join-Path $RepoRoot 'tools\dev\enforce_utf8_bom_lf_changed.ps1'
            Args = @('-Mode', 'fix', '-Policy', 'enforce', '-IncludeUntracked')
        },
        [pscustomobject]@{
            Name = 'src'
            ScriptPath = Join-Path $RepoRoot 'tools\dev\enforce_utf8_lf_src_changed.ps1'
            Args = @('-Mode', 'fix', '-Policy', 'enforce', '-IncludeUntracked')
        }
    )

    foreach ($gate in $gateSpecs) {
        $gateScriptPath = [string]$gate.ScriptPath
        $resolvedGateScriptPath = ''
        try {
            if (-not [string]::IsNullOrWhiteSpace($gateScriptPath)) {
                $fullGateScriptPath = [System.IO.Path]::GetFullPath($gateScriptPath)
                if ([System.IO.File]::Exists($fullGateScriptPath)) {
                    $resolvedGateScriptPath = $fullGateScriptPath
                }
            }
        }
        catch {
            $resolvedGateScriptPath = ''
        }

        if ([string]::IsNullOrWhiteSpace($resolvedGateScriptPath)) {
            throw ("[{0}] pre-v1 encoding gate script missing: {1}" -f $ScriptTag, $gateScriptPath)
        }

        $lines = @()
        $exitCode = 1
        try {
            # Build named parameter splat for robust invocation (supports switches)
            $paramHash = @{}
            $argList = @($gate.Args | ForEach-Object { [string]$_ })
            for ($i = 0; $i -lt $argList.Count; ) {
                $token = $argList[$i]
                if ($token -like '-*') {
                    $key = $token.TrimStart('-')
                    if ($i + 1 -lt $argList.Count -and ($argList[$i+1] -notlike '-*')) {
                        $paramHash[$key] = $argList[$i+1]
                        $i += 2
                    }
                    else {
                        $paramHash[$key] = $true
                        $i += 1
                    }
                }
                else { $i += 1 }
            }

            $lines = @((& $resolvedGateScriptPath @paramHash 2>&1) | ForEach-Object { [string]$_ })
            $exitCode = 0
            if (Test-Path Variable:LASTEXITCODE) {
                $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
            }
            else {
                try {
                    $g = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction Stop
                    if ($null -ne $g.Value) { $exitCode = [int]$g.Value } else { $exitCode = 0 }
                }
                catch {
                    $exitCode = 0
                }
            }
        }
        catch {
            $errorText = Convert-ToSingleLineText -Text $_.Exception.Message
            if (-not [string]::IsNullOrWhiteSpace($errorText)) {
                $lines = @($errorText)
            }

            try {
                $g = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction Stop
                if ($null -ne $g.Value) { $exitCode = [int]$g.Value } else { $exitCode = 1 }
            }
            catch {
                $exitCode = 1
            }
        }

        foreach ($line in @($lines)) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-Output $line
            }
        }

        if ($exitCode -ne 0) {
            $detailLines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            $detail = if ($detailLines.Count -gt 0) {
                Convert-ToSingleLineText -Text ($detailLines -join ' | ')
            }
            else {
                'no-output'
            }

            throw ("[{0}] pre-v1 encoding gate failed gate={1} exit={2} detail={3}" -f $ScriptTag, [string]$gate.Name, $exitCode, $detail)
        }

        Write-Output ("[{0}] pre_v1_encoding_gate={1} status=PASS mode=fix policy=enforce" -f $ScriptTag, [string]$gate.Name)
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath
$monitorTimelinePath = Get-MonitorTimelinePath -StartFilePath $startFilePath -RepoRoot $repoRoot
Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{ MONITOR_CHAIN_TIMELINE = (Convert-ToAnchorPath -Path $monitorTimelinePath) }
Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'stage_window_invoke' -Fields @{
    stage = $Stage
    start_file = (Convert-ToAnchorPath -Path $startFilePath)
    start_monitors = [bool]$StartMonitors.IsPresent
    skip_monitor_restart = [bool]$SkipMonitorRestart.IsPresent
    enable_b_monitor_restart = [bool]$EnableBMonitorRestart.IsPresent
}
$settings = Invoke-DispatchDeliveryToggle -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
Invoke-PreV1EncodingFixGates -RepoRoot $repoRoot -ScriptTag 'OPEN-AB-STAGE'
Invoke-LaunchReadyGate -Stage $Stage -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE' -RepoRoot $repoRoot
$settings = Read-KeyValueFile -Path $startFilePath
$settings = Invoke-DispatchDeliveryToggle -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
Assert-PrecheckGateReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE'
Assert-NetworkPrecheckReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE' -RepoRoot $repoRoot
$settings = Read-KeyValueFile -Path $startFilePath
$settings = Invoke-DispatchDeliveryToggle -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
$bRestartModeRequested = ($Stage -eq 'B' -and $EnableBMonitorRestart.IsPresent)
$bLaunchPlan = Assert-BStartEligibility -Stage $Stage -Settings $settings -StartFilePath $startFilePath -RepoRoot $repoRoot -ScriptTag 'OPEN-AB-STAGE' -BRestartModeRequested $bRestartModeRequested
if ($null -ne $bLaunchPlan -and $bLaunchPlan.PSObject.Properties.Name -contains 'UpdatedSettings' -and $null -ne $bLaunchPlan.UpdatedSettings) {
    $settings = [System.Collections.IDictionary]$bLaunchPlan.UpdatedSettings
}
$bRestartModeForGate = if ($Stage -eq 'B') { [bool]$bLaunchPlan.EffectiveRestartMode } else { $false }

$previousAFinalStatus = if ($settings.Contains('A_FINAL_STATUS')) {
    [string]$settings.A_FINAL_STATUS
}
else {
    ''
}
$previousBFinalStatus = if ($settings.Contains('B_FINAL_STATUS')) {
    [string]$settings.B_FINAL_STATUS
}
else {
    ''
}

if (-not (Test-StageLaunchAllowed -Stage $Stage -Settings $settings -ScriptTag 'OPEN-AB-STAGE')) {
    exit 0
}

$settings = Clear-MonitorChainShutdownRequest -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'

# ── Stage process cleanup is owned by the fastmode main-mutex gate. ──
# Do not terminate command-line matches here: a live same-stage process must
# retain ownership until its main mutex is released.
$entryScriptKey = if ($Stage -eq 'A') { 'ENTRY_SCRIPT_A' } else { 'ENTRY_SCRIPT_B' }
Write-Output ('[OPEN-AB-STAGE] stage_process_cleanup stage={0} action=defer-to-main-mutex' -f $Stage)

$taskKey = if ($Stage -eq 'A') { 'A_TASK_DEFINITION' } else { 'B_TASK_DEFINITION' }

$entryScriptPath = Resolve-RepoPath -Path ([string]$settings[$entryScriptKey])
$taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName ([string]$settings[$taskKey]) -SettingKey $taskKey
$null = Resolve-RepoPath -Path $taskDefinitionRelative

# ── Pre-source baseline: restore target file before static precheck ──
$taskDefPath = Resolve-RepoPath -Path $taskDefinitionRelative
$taskTargetFile = ''
if (Test-Path -LiteralPath $taskDefPath) {
    try {
        $taskDefJson = Get-Content -LiteralPath $taskDefPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $taskDefJson -and ($taskDefJson.PSObject.Properties.Name -contains 'targetFile')) {
            $taskTargetFile = [string]$taskDefJson.targetFile
        }
    }
    catch {
        $taskTargetFile = ''
    }
}

if (-not [string]::IsNullOrWhiteSpace($taskTargetFile)) {
    $resolvedTargetFile = Resolve-RepoPath -Path $taskTargetFile
    if (-not [string]::IsNullOrWhiteSpace($resolvedTargetFile) -and (Test-Path -LiteralPath $resolvedTargetFile)) {
        if ($Stage -eq 'A') {
            # Stage A: restore target file to git baseline (clean any residual changes from prior runs)
            & git -C $repoRoot checkout -- $resolvedTargetFile 2>$null
            Write-Output ("[OPEN-AB-STAGE] source_restore stage=A target={0} action=git-checkout" -f $taskTargetFile)
        }
        elseif ($Stage -eq 'B') {
            # Stage B: restore target file from A success snapshot
            $bRestoreSourceDir = ''
            if ($settings.Contains('A_SUCCESS_SNAPSHOT_FINAL_STATUS')) {
                $snapStatusRaw = [string]$settings.A_SUCCESS_SNAPSHOT_FINAL_STATUS
                $snapStatusPath = Resolve-RepoPathAllowMissing -Path $snapStatusRaw -RepoRoot $repoRoot
                if (-not [string]::IsNullOrWhiteSpace($snapStatusPath) -and (Test-Path -LiteralPath $snapStatusPath)) {
                    $snapDir = Join-Path (Split-Path -Parent $snapStatusPath) 'a_success_snapshot'
                    $bRestoreSourceDir = Join-Path $snapDir 'source'
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($bRestoreSourceDir) -and (Test-Path -LiteralPath $bRestoreSourceDir)) {
                $snapshotTargetPath = Join-Path $bRestoreSourceDir $taskTargetFile
                if (Test-Path -LiteralPath $snapshotTargetPath) {
                    Copy-Item -LiteralPath $snapshotTargetPath -Destination $resolvedTargetFile -Force
                    Write-Output ("[OPEN-AB-STAGE] source_restore stage=B target={0} action=snapshot-restore snapshot_dir={1}" -f $taskTargetFile, (Convert-ToAnchorPath -Path $snapDir))
                }
                else {
                    Write-Output ("[OPEN-AB-STAGE] source_restore stage=B target={0} action=snapshot-missing snapshot_dir={1}" -f $taskTargetFile, (Convert-ToAnchorPath -Path $snapDir))
                }
            }
            else {
                Write-Output ("[OPEN-AB-STAGE] source_restore stage=B target={0} action=snapshot-unavailable" -f $taskTargetFile)
            }
        }
    }
}

# Clean up stale remote build processes and lock BEFORE killing local processes.
# Order: remote kill -> remote lock cleanup -> local stale process cleanup.
# This prevents orphaned remote builds from continuing after local one_click_release is killed.
try {
    $sshCleanupPath = 'C:\Windows\System32\OpenSSH\ssh.exe'
    if (Test-Path $sshCleanupPath) {
        $remoteTarget = 'larson@10.0.0.199'
        $remoteBase = '/home/larson/whois_remote'
        $remoteLockDir = "$remoteBase/.remote_build.lock"
        & $sshCleanupPath -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no $remoteTarget @"
pkill -f 'whois_remote' 2>/dev/null || true
sleep 1
rm -rf '$remoteLockDir' 2>/dev/null
echo REMOTE_CLEANUP_DONE
"@ 2>&1 | Out-Null
        Write-Output ("[OPEN-AB-STAGE] remote_build_cleanup host=10.0.0.199")
    }
}
catch {
    Write-Output ("[OPEN-AB-STAGE] remote_build_cleanup_skipped detail={0}" -f $_.Exception.Message)
}

# Clean up stale one_click_release.ps1 processes from prior A stage runs
$staleBuildName = 'one_click_release.ps1'
try {
    $staleBuildProcesses = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction Stop |
        Where-Object { $_.CommandLine -match [regex]::Escape($staleBuildName) }
    foreach ($staleProc in $staleBuildProcesses) {
        $stalePid = [int]$staleProc.ProcessId
        if ($stalePid -gt 0 -and $stalePid -ne $PID) {
            try {
                $sp = Get-Process -Id $stalePid -ErrorAction Stop
                if (-not $sp.HasExited) {
                    $sp.Kill()
                    Write-Output ("[OPEN-AB-STAGE] stale_build_cleanup pid={0} script={1}" -f $stalePid, $staleBuildName)
                }
            }
            catch { $null = $_ }
        }
    }
}
catch { $null = $_ }

$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$taskStaticPrecheckPolicy = 'enforce'
if ($settings.Contains('TASK_STATIC_PRECHECK_POLICY')) {
    $policyCandidate = (Convert-ToSingleLineText -Text ([string]$settings.TASK_STATIC_PRECHECK_POLICY)).ToLowerInvariant()
    if ($policyCandidate -in @('off', 'warn', 'enforce')) {
        $taskStaticPrecheckPolicy = $policyCandidate
    }
}

$taskStaticPrecheckFailOnWarnings = $false
if ($settings.Contains('TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS')) {
    $taskStaticPrecheckFailOnWarnings = Convert-ToBooleanSetting -Value ([string]$settings.TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS) -Default $false
}

$taskStaticPrecheckMaxFails = 3
if ($settings.Contains('TASK_STATIC_PRECHECK_MAX_FAILS')) {
    $parsedMaxFails = Get-ParsedPositiveInt -Value ([string]$settings.TASK_STATIC_PRECHECK_MAX_FAILS)
    if ($parsedMaxFails -gt 0) {
        $taskStaticPrecheckMaxFails = $parsedMaxFails
    }
}

$taskStaticPrecheckBlockEvent = 'manual-wait-paused'
if ($settings.Contains('TASK_STATIC_PRECHECK_BLOCK_EVENT')) {
    $blockEventCandidate = (Convert-ToSingleLineText -Text ([string]$settings.TASK_STATIC_PRECHECK_BLOCK_EVENT)).ToLowerInvariant()
    if ($blockEventCandidate -in @('manual-wait-paused', 'recovery-await-confirmation', 'task-definition-fix-required')) {
        $taskStaticPrecheckBlockEvent = $blockEventCandidate
    }
}

$taskStaticPrecheckFailCount = 0
if ($settings.Contains('TASK_STATIC_PRECHECK_FAIL_COUNT')) {
    $taskStaticPrecheckFailCount = Get-ParsedPositiveInt -Value ([string]$settings.TASK_STATIC_PRECHECK_FAIL_COUNT)
}

$taskStaticPrecheckScript = Join-Path $repoRoot 'tools\test\check_task_definition_static.ps1'
if (-not (Test-Path -LiteralPath $taskStaticPrecheckScript)) {
    throw "[OPEN-AB-STAGE] missing static precheck script: $taskStaticPrecheckScript"
}

$taskStaticPrecheckEnabled = ($Stage -eq 'A')
if ($taskStaticPrecheckEnabled) {
    $precheckScopeRoundTag = 'D1'
    $precheckScopeOperationIndex = 1
    $resumeFailedRound = if ($settings.Contains('RESUME_FAILED_ROUND')) {
        (Convert-ToSingleLineText -Text ([string]$settings.RESUME_FAILED_ROUND)).ToUpperInvariant()
    }
    else {
        ''
    }
    if ($resumeFailedRound -match '^D[1-4]$') {
        $precheckScopeRoundTag = $resumeFailedRound
        $precheckScopeOperationIndex = 0
    }

    $precheckArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $taskStaticPrecheckScript,
        '-TaskDefinitionFile', $taskDefinitionRelative,
        '-Policy', $taskStaticPrecheckPolicy,
        '-RoundTag', $precheckScopeRoundTag,
        '-StartFilePath', $startFilePath,
        '-Stage', $Stage,
        '-EnableFingerprintCheck'
    )
    if ($precheckScopeOperationIndex -gt 0) {
        $precheckArgs += @('-OperationIndex', [string]$precheckScopeOperationIndex)
    }
    if ($taskStaticPrecheckFailOnWarnings) {
        $precheckArgs += '-FailOnWarnings'
    }

    $precheckOutput = @(& $powershellPath @precheckArgs 2>&1)
    $precheckExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    foreach ($precheckLine in $precheckOutput) {
        Write-Output ([string]$precheckLine)
    }
    if ($precheckExitCode -ne 0) {
        $failureLocation = Get-TaskStaticFailureLocation -Lines @($precheckOutput | ForEach-Object { [string]$_ }) -FallbackRound $precheckScopeRoundTag
        $taskStaticPrecheckFailCount += 1
        $precheckFailUpdates = @{
            TASK_STATIC_PRECHECK_FAIL_COUNT = [string]$taskStaticPrecheckFailCount
            TASK_STATIC_PRECHECK_LAST_FAIL_STAGE = $Stage
            TASK_STATIC_PRECHECK_LAST_FAIL_AT = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK')
        }
        Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values $precheckFailUpdates

        $overLimit = ($taskStaticPrecheckFailCount -gt $taskStaticPrecheckMaxFails)
        if (-not $overLimit) {
            Add-StageTaskDefinitionFixTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount $taskStaticPrecheckFailCount -MaxFails $taskStaticPrecheckMaxFails -PrecheckExitCode $precheckExitCode -MainRound ([string]$failureLocation.Round) -FailureOperation ([int]$failureLocation.Operation) -FailurePhase 'static-precheck' -FailureEvidence ([string]$failureLocation.Evidence)
        }
        if ($overLimit) {
            Add-StageTaskDefinitionBlockedTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount $taskStaticPrecheckFailCount -MaxFails $taskStaticPrecheckMaxFails -PrecheckExitCode $precheckExitCode -BlockEvent $taskStaticPrecheckBlockEvent -MainRound ([string]$failureLocation.Round) -FailureOperation ([int]$failureLocation.Operation) -FailurePhase 'static-precheck' -FailureEvidence ([string]$failureLocation.Evidence)
            throw ("[OPEN-AB-STAGE] task static precheck failed and blocked: fail_count={0} limit={1} exit={2} stage={3} task={4} scope={5}:op{6}" -f $taskStaticPrecheckFailCount, $taskStaticPrecheckMaxFails, $precheckExitCode, $Stage, $taskDefinitionRelative, $precheckScopeRoundTag, $precheckScopeOperationIndex)
        }

        throw ("[OPEN-AB-STAGE] task static precheck failed exit={0} stage={1} task={2} fail_count={3} limit={4} scope={5}:op{6}" -f $precheckExitCode, $Stage, $taskDefinitionRelative, $taskStaticPrecheckFailCount, $taskStaticPrecheckMaxFails, $precheckScopeRoundTag, $precheckScopeOperationIndex)
    }

    if ($taskStaticPrecheckFailCount -gt 0 -or $settings.Contains('TASK_STATIC_PRECHECK_FAIL_COUNT')) {
        Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
            TASK_STATIC_PRECHECK_FAIL_COUNT = '0'
            TASK_STATIC_PRECHECK_LAST_PASS_STAGE = $Stage
            TASK_STATIC_PRECHECK_LAST_PASS_AT = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK')
        }
    }
    Write-Output ("[OPEN-AB-STAGE] task_static_precheck status=PASS stage={0} scope={1}:op{2} policy={3} fail_on_warnings={4} fail_count=0 limit={5}" -f $Stage, $precheckScopeRoundTag, $precheckScopeOperationIndex, $taskStaticPrecheckPolicy, [string]$taskStaticPrecheckFailOnWarnings, $taskStaticPrecheckMaxFails)
}
else {
    Write-Output ("[OPEN-AB-STAGE] task_static_precheck status=SKIP stage={0} reason=stage-policy runtime_fail_fast=enabled" -f $Stage)
}

Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_IP' -Settings $settings -Key 'REMOTE_IP'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_USER' -Settings $settings -Key 'REMOTE_USER'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_KEYPATH' -Settings $settings -Key 'REMOTE_KEYPATH'
Invoke-EnvFromSetting -EnvName 'AUTO_QUERIES' -Settings $settings -Key 'QUERIES'
Invoke-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_MODE' -Settings $settings -Key 'TERMINAL_WATCHDOG_MODE'
Invoke-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC' -Settings $settings -Key 'TERMINAL_WATCHDOG_INTERVAL_SEC'
Invoke-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC' -Settings $settings -Key 'TERMINAL_WATCHDOG_MIN_AGE_SEC'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_REQUIRED' -Settings $settings -Key 'REMOTE_BUILD_LOCK_REQUIRED'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_SCOPE' -Settings $settings -Key 'REMOTE_BUILD_LOCK_SCOPE'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_CONFLICT_ACTION' -Settings $settings -Key 'REMOTE_BUILD_LOCK_CONFLICT_ACTION'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRED'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_LOCAL_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_LOCAL_REQUIRED'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REMOTE_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REMOTE_REQUIRED'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV4'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV6'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV4'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV6'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TARGETS' -Settings $settings -Key 'NETWORK_PRECHECK_TARGETS'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TIMEOUT_SEC' -Settings $settings -Key 'NETWORK_PRECHECK_TIMEOUT_SEC'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_ENABLED' -Settings $settings -Key 'ROUND_RUNTIME_GATE_ENABLED'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_START_ROUND' -Settings $settings -Key 'ROUND_RUNTIME_GATE_START_ROUND'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MAX_ATTEMPTS' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MAX_ATTEMPTS'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_RETRY_DELAY_SEC' -Settings $settings -Key 'ROUND_RUNTIME_GATE_RETRY_DELAY_SEC'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_NETWORK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_NETWORK'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT'
Invoke-EnvFromSetting -EnvName 'AUTO_TASK_STATIC_PRECHECK_POLICY' -Settings $settings -Key 'TASK_STATIC_PRECHECK_POLICY'
Invoke-EnvFromSetting -EnvName 'AUTO_TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS' -Settings $settings -Key 'TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS'
Invoke-EnvFromSetting -EnvName 'AUTO_RESUME_FAILED_ROUND' -Settings $settings -Key 'RESUME_FAILED_ROUND'
if ($Stage -eq 'A') {
    # Anti-infinite-loop gate for A stage: detect consecutive identical failures
    $aFailureFingerprint = if ($settings.Contains('A_FAILURE_FINGERPRINT')) { [string]$settings.A_FAILURE_FINGERPRINT } else { '' }
    $aFailureMainRound = if ($settings.Contains('A_FAILURE_MAIN_ROUND')) { [string]$settings.A_FAILURE_MAIN_ROUND } else { '' }
    $aFailurePhase = if ($settings.Contains('A_FAILURE_PHASE')) { [string]$settings.A_FAILURE_PHASE } else { '' }
    $aFailureTaskStartAt = if ($settings.Contains('A_FAILURE_TASK_START_AT')) { [string]$settings.A_FAILURE_TASK_START_AT } else { '' }
    $aPreviousFailureFingerprint = if ($settings.Contains('A_PREVIOUS_FAILURE_FINGERPRINT')) { [string]$settings.A_PREVIOUS_FAILURE_FINGERPRINT } else { '' }
    $aPreviousFailureMainRound = if ($settings.Contains('A_PREVIOUS_FAILURE_MAIN_ROUND')) { [string]$settings.A_PREVIOUS_FAILURE_MAIN_ROUND } else { '' }
    $aPreviousFailurePhase = if ($settings.Contains('A_PREVIOUS_FAILURE_PHASE')) { [string]$settings.A_PREVIOUS_FAILURE_PHASE } else { '' }
    $aPreviousFailureTaskStartAt = if ($settings.Contains('A_PREVIOUS_FAILURE_TASK_START_AT')) { [string]$settings.A_PREVIOUS_FAILURE_TASK_START_AT } else { '' }
    $aFailureTaskDefHash = if ($settings.Contains('A_FAILURE_TASKDEF_HASH')) { [string]$settings.A_FAILURE_TASKDEF_HASH } else { '' }
    $aPreviousFailureTaskDefHash = if ($settings.Contains('A_PREVIOUS_FAILURE_TASKDEF_HASH')) { [string]$settings.A_PREVIOUS_FAILURE_TASKDEF_HASH } else { '' }
    $aFailureSourceHash = if ($settings.Contains('A_FAILURE_SOURCE_HASH')) { [string]$settings.A_FAILURE_SOURCE_HASH } else { '' }
    $aPreviousFailureSourceHash = if ($settings.Contains('A_PREVIOUS_FAILURE_SOURCE_HASH')) { [string]$settings.A_PREVIOUS_FAILURE_SOURCE_HASH } else { '' }
    $aFailureRoundImprintHash = if ($settings.Contains('A_FAILURE_TASKDEF_ROUND_IMPRINT_HASH')) { [string]$settings.A_FAILURE_TASKDEF_ROUND_IMPRINT_HASH } else { '' }
    $aPreviousFailureRoundImprintHash = if ($settings.Contains('A_PREVIOUS_FAILURE_TASKDEF_ROUND_IMPRINT_HASH')) { [string]$settings.A_PREVIOUS_FAILURE_TASKDEF_ROUND_IMPRINT_HASH } else { '' }

    $aRetryGrantKey = 'A_CODESTEP_IDENTICAL_FP_RETRY_GRANTED_FOR'
    $aRetryGrantAtKey = 'A_CODESTEP_IDENTICAL_FP_RETRY_GRANTED_AT'
    $aRetryCountKey = 'A_CODESTEP_IDENTICAL_FP_RETRY_COUNT'
    $aRetryStateKey = 'A_CODESTEP_IDENTICAL_FP_STATE'
    $aRetryStateAtKey = 'A_CODESTEP_IDENTICAL_FP_STATE_AT'
    $aRetryMax = 3
    if ($settings.Contains('CODESTEP_IDENTICAL_FP_MAX_RETRIES')) {
        $parsedGlobalRetryMax = Get-ParsedPositiveInt -Value ([string]$settings.CODESTEP_IDENTICAL_FP_MAX_RETRIES)
        if ($parsedGlobalRetryMax -gt 0) { $aRetryMax = $parsedGlobalRetryMax }
    }
    if ($settings.Contains('A_CODESTEP_IDENTICAL_FP_MAX_RETRIES')) {
        $parsedStageRetryMax = Get-ParsedPositiveInt -Value ([string]$settings.A_CODESTEP_IDENTICAL_FP_MAX_RETRIES)
        if ($parsedStageRetryMax -gt 0) { $aRetryMax = $parsedStageRetryMax }
    }

    if (-not [string]::IsNullOrWhiteSpace($aFailureTaskStartAt) -and
        -not [string]::IsNullOrWhiteSpace($aPreviousFailureTaskStartAt) -and
        $aFailureTaskStartAt -ne '-' -and
        $aPreviousFailureTaskStartAt -ne '-' -and
        $aFailureTaskStartAt -ne $aPreviousFailureTaskStartAt) {
        Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
            $aRetryGrantKey = ''
            $aRetryGrantAtKey = ''
            $aRetryCountKey = '0'
            $aRetryStateKey = ''
            $aRetryStateAtKey = ''
        }
        Write-Output ("[OPEN-AB-STAGE] identical_fp_retry_reset stage=A reason=task_start_window_changed previous={0} current={1}" -f $aPreviousFailureTaskStartAt, $aFailureTaskStartAt)
    }
    $aSameTaskStartWindow = $true
    if (-not [string]::IsNullOrWhiteSpace($aFailureTaskStartAt) -and
        -not [string]::IsNullOrWhiteSpace($aPreviousFailureTaskStartAt) -and
        $aFailureTaskStartAt -ne '-' -and
        $aPreviousFailureTaskStartAt -ne '-') {
        $aSameTaskStartWindow = ($aFailureTaskStartAt -eq $aPreviousFailureTaskStartAt)
    }
    if (-not [string]::IsNullOrWhiteSpace($aFailureMainRound) -and
        -not [string]::IsNullOrWhiteSpace($aPreviousFailureMainRound) -and
        $aFailureMainRound -eq $aPreviousFailureMainRound -and
        -not [string]::IsNullOrWhiteSpace($aFailurePhase) -and
        -not [string]::IsNullOrWhiteSpace($aPreviousFailurePhase) -and
        $aFailurePhase -eq $aPreviousFailurePhase -and
        $aSameTaskStartWindow -and
        -not [string]::IsNullOrWhiteSpace($aFailureFingerprint) -and
        -not [string]::IsNullOrWhiteSpace($aPreviousFailureFingerprint) -and
        $aFailureFingerprint -eq $aPreviousFailureFingerprint) {

        $aRetryCount = 0
        if ($settings.Contains($aRetryCountKey)) {
            $aRetryCount = Get-ParsedPositiveInt -Value ([string]$settings[$aRetryCountKey])
        }
        $aTaskDefChanged = (-not [string]::IsNullOrWhiteSpace($aFailureTaskDefHash) -and -not [string]::IsNullOrWhiteSpace($aPreviousFailureTaskDefHash) -and $aFailureTaskDefHash -ne '-' -and $aPreviousFailureTaskDefHash -ne '-' -and $aFailureTaskDefHash -ne $aPreviousFailureTaskDefHash)
        $aSourceChanged = (-not [string]::IsNullOrWhiteSpace($aFailureSourceHash) -and -not [string]::IsNullOrWhiteSpace($aPreviousFailureSourceHash) -and $aFailureSourceHash -ne '-' -and $aPreviousFailureSourceHash -ne '-' -and $aFailureSourceHash -ne $aPreviousFailureSourceHash)
        $aImprintChanged = (-not [string]::IsNullOrWhiteSpace($aFailureRoundImprintHash) -and -not [string]::IsNullOrWhiteSpace($aPreviousFailureRoundImprintHash) -and $aFailureRoundImprintHash -ne '-' -and $aPreviousFailureRoundImprintHash -ne '-' -and $aFailureRoundImprintHash -ne $aPreviousFailureRoundImprintHash)
        $aCurrentEvidence = Get-TaskDefinitionRepairEvidence -TaskDefinitionPath $taskDefinitionRelative -Round $aFailureMainRound
        $aCurrentTaskDefChanged = (-not [string]::IsNullOrWhiteSpace($aFailureTaskDefHash) -and $aFailureTaskDefHash -ne '-' -and -not [string]::IsNullOrWhiteSpace([string]$aCurrentEvidence.FileHash) -and [string]$aCurrentEvidence.FileHash -ne $aFailureTaskDefHash)
        $aCurrentImprintChanged = (-not [string]::IsNullOrWhiteSpace($aFailureRoundImprintHash) -and $aFailureRoundImprintHash -ne '-' -and -not [string]::IsNullOrWhiteSpace([string]$aCurrentEvidence.RoundImprintHash) -and [string]$aCurrentEvidence.RoundImprintHash -ne $aFailureRoundImprintHash)
        $aHasRepairEvidence = ($aTaskDefChanged -or $aSourceChanged -or $aImprintChanged -or $aCurrentTaskDefChanged -or $aCurrentImprintChanged)
        $aCurrentState = if ($settings.Contains($aRetryStateKey)) { (Convert-ToSingleLineText -Text ([string]$settings[$aRetryStateKey])).ToLowerInvariant() } else { '' }

        if ($aFailurePhase -eq 'code-step' -and $aCurrentState -eq 'hard_block' -and $aHasRepairEvidence) {
            Write-Output ("[OPEN-AB-STAGE] identical_fp_state_unlock stage=A reason=repair_evidence_detected round={0} task_start_at={1}" -f $aFailureMainRound, $aFailureTaskStartAt)
            $aRetryCount = 0
            $aCurrentState = ''
            Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
                $aRetryCountKey = '0'
                $aRetryStateKey = 'pending_review'
                $aRetryStateAtKey = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
            }
        }

        if ($aFailurePhase -eq 'code-step' -and $aRetryCount -lt $aRetryMax) {
            $aNextAttempt = $aRetryCount + 1
            if ($aNextAttempt -gt 1 -and -not $aHasRepairEvidence) {
                Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
                    $aRetryStateKey = 'hard_block'
                    $aRetryStateAtKey = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
                }
                Add-StageTaskDefinitionBlockedTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount $aNextAttempt -MaxFails $aRetryMax -PrecheckExitCode 0 -BlockEvent 'manual-wait-paused' -ExtraDetail ("fingerprint_duplicate=true retry_budget_exhausted=true retry_requires_evidence=true retry_count={0} retry_limit={1} round={2} phase={3} task_start_at={4} fingerprint={5}" -f $aRetryCount, $aRetryMax, $aFailureMainRound, $aFailurePhase, $aFailureTaskStartAt, $aFailureFingerprint) -RecommendedActionOverride 'Identical fingerprint retried without effective repair evidence. AI must change repair method (not same patch shape), adjust round operations/anchors, and produce evidence-changing edits before relaunch. Stop auto-retry, perform manual task-definition fix, pass static check, then relaunch.' -FailureCategoryOverride 'fingerprint-duplicate-manual-escalation' -FailureKindOverride 'fingerprint-duplicate-evidence-missing'
                throw ("[OPEN-AB-STAGE] infinite-loop-protection: A identical code-step fingerprint detected without repair evidence (round={0}, task_start_at={1}, fingerprint={2}). Manual intervention required." -f $aFailureMainRound, $aFailureTaskStartAt, $aFailureFingerprint)
            }

            $aRetryGrantedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
            Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
                $aRetryGrantKey = $aFailureFingerprint
                $aRetryGrantAtKey = $aRetryGrantedAt
                $aRetryCountKey = [string]$aNextAttempt
                $aRetryStateKey = 'override_window'
                $aRetryStateAtKey = $aRetryGrantedAt
            }
            Add-StageTaskDefinitionFixTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount $aNextAttempt -MaxFails $aRetryMax -PrecheckExitCode 0 -MainRound $aFailureMainRound -FailurePhase $aFailurePhase -FailureFingerprint $aFailureFingerprint -TaskStartAt $aFailureTaskStartAt -RetryAttempt $aNextAttempt -RetryMax $aRetryMax
            throw ("[OPEN-AB-STAGE] infinite-loop-protection: A identical code-step fingerprint detected (main_round={0}, phase={1}, task_start_at={2}, fingerprint={3}). Retry granted {4}/{5}; apply task-definition fix and relaunch." -f $aFailureMainRound, $aFailurePhase, $aFailureTaskStartAt, $aFailureFingerprint, $aNextAttempt, $aRetryMax)
        }

        if ($aFailurePhase -eq 'code-step') {
            Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
                $aRetryStateKey = 'hard_block'
                $aRetryStateAtKey = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
            }
            Add-StageTaskDefinitionBlockedTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount ($aRetryCount + 1) -MaxFails $aRetryMax -PrecheckExitCode 0 -BlockEvent 'manual-wait-paused' -ExtraDetail ("fingerprint_duplicate=true retry_budget_exhausted=true retry_count={0} retry_limit={1} round={2} phase={3} task_start_at={4} fingerprint={5}" -f $aRetryCount, $aRetryMax, $aFailureMainRound, $aFailurePhase, $aFailureTaskStartAt, $aFailureFingerprint) -RecommendedActionOverride 'Fingerprint duplicate repeated after retry budget exhaustion. AI must switch to a different fix strategy (e.g., rewrite round op anchors/ordering or append-mode patch) instead of repeating prior edits. Stop auto self-heal and transfer to manual intervention only.' -FailureCategoryOverride 'fingerprint-duplicate-manual-escalation' -FailureKindOverride 'fingerprint-duplicate-retry-exhausted'
        }

        throw ("[OPEN-AB-STAGE] infinite-loop-protection: A failed repeatedly with identical fingerprint (main_round={0}, phase={1}, task_start_at={2}, fingerprint={3}). Retry budget exhausted; manual intervention required." -f $aFailureMainRound, $aFailurePhase, $aFailureTaskStartAt, $aFailureFingerprint)
    }

    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_ENABLED' -Value 'true'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_START_ROUND' -Value '1'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_END_ROUND' -Value '8'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_OPERATION_INDEX' -Value '0'
    Set-Item -Path 'Env:AUTO_FASTMODE_GATE_END_ROUND' -Value '8'
}
else {
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_ENABLED' -Value 'true'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_START_ROUND' -Value '1'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_END_ROUND' -Value '8'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_OPERATION_INDEX' -Value '0'
    Set-Item -Path 'Env:AUTO_FASTMODE_GATE_END_ROUND' -Value '8'
}
Remove-Item -Path 'Env:AUTO_KEEP_WINDOW_ON_EXIT' -ErrorAction SilentlyContinue
Invoke-EnvFromSetting -EnvName 'AUTO_KEEP_WINDOW_ON_EXIT' -Settings $settings -Key 'KEEP_WINDOW_ON_EXIT'

Remove-Item -Path 'Env:AUTO_A_PREVIOUS_FINAL_STATUS' -ErrorAction SilentlyContinue
Remove-Item -Path 'Env:AUTO_B_PREVIOUS_FINAL_STATUS' -ErrorAction SilentlyContinue
Remove-Item -Path 'Env:AUTO_B_RESTORE_FROM_A_SNAPSHOT' -ErrorAction SilentlyContinue
Remove-Item -Path 'Env:AUTO_B_A_SNAPSHOT_DIR' -ErrorAction SilentlyContinue

if ($Stage -eq 'B') {
    Set-Item -Path 'Env:AUTO_A_PREVIOUS_FINAL_STATUS' -Value $previousAFinalStatus
    Set-Item -Path 'Env:AUTO_B_PREVIOUS_FINAL_STATUS' -Value $previousBFinalStatus

    $restoreFromASnapshot = if ($bRestartModeForGate) { 'true' } else { 'false' }
    $restoreDecisionReason = if ($bRestartModeForGate) { 'auto-mode=restart' } else { 'auto-mode=normal' }

    Set-Item -Path 'Env:AUTO_B_RESTORE_FROM_A_SNAPSHOT' -Value $restoreFromASnapshot

    $snapshotDirHint = ''
    if ($null -ne $bLaunchPlan -and $bLaunchPlan.PSObject.Properties.Name -contains 'SnapshotDir') {
        $snapshotDirHint = [string]$bLaunchPlan.SnapshotDir
    }

    if ($settings.Contains('SESSION_FINAL_NOTES')) {
        if ([string]::IsNullOrWhiteSpace($snapshotDirHint)) {
            $snapshotDirHint = Get-LatestAnchorValueFromNoteText -Notes ([string]$settings.SESSION_FINAL_NOTES) -Key 'a_snapshot_dir'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($snapshotDirHint)) {
        Set-Item -Path 'Env:AUTO_B_A_SNAPSHOT_DIR' -Value $snapshotDirHint
    }

    Write-Output ("[OPEN-AB-STAGE] b_restore_decision previous_a={0} previous_b={1} restore={2} reason={3}" -f $previousAFinalStatus, $previousBFinalStatus, $restoreFromASnapshot, $restoreDecisionReason)

    # Anti-infinite-loop gate: detect consecutive identical B failures
    # before launching. Reads failure fingerprint from start file (written
    # by guard on incident-captured). If main_round+fingerprint match the
    # previous failure consecutively, the self-healing fix did not take
    # effect — block restart to avoid infinite loop.
    $bFailureFingerprint = if ($settings.Contains('B_FAILURE_FINGERPRINT')) { [string]$settings.B_FAILURE_FINGERPRINT } else { '' }
    $bFailureMainRound = if ($settings.Contains('B_FAILURE_MAIN_ROUND')) { [string]$settings.B_FAILURE_MAIN_ROUND } else { '' }
    $bFailurePhase = if ($settings.Contains('B_FAILURE_PHASE')) { [string]$settings.B_FAILURE_PHASE } else { '' }
    $bFailureTaskStartAt = if ($settings.Contains('B_FAILURE_TASK_START_AT')) { [string]$settings.B_FAILURE_TASK_START_AT } else { '' }
    $bPreviousFailureFingerprint = if ($settings.Contains('B_PREVIOUS_FAILURE_FINGERPRINT')) { [string]$settings.B_PREVIOUS_FAILURE_FINGERPRINT } else { '' }
    $bPreviousFailureMainRound = if ($settings.Contains('B_PREVIOUS_FAILURE_MAIN_ROUND')) { [string]$settings.B_PREVIOUS_FAILURE_MAIN_ROUND } else { '' }
    $bPreviousFailurePhase = if ($settings.Contains('B_PREVIOUS_FAILURE_PHASE')) { [string]$settings.B_PREVIOUS_FAILURE_PHASE } else { '' }
    $bPreviousFailureTaskStartAt = if ($settings.Contains('B_PREVIOUS_FAILURE_TASK_START_AT')) { [string]$settings.B_PREVIOUS_FAILURE_TASK_START_AT } else { '' }
    $bFailureTaskDefHash = if ($settings.Contains('B_FAILURE_TASKDEF_HASH')) { [string]$settings.B_FAILURE_TASKDEF_HASH } else { '' }
    $bPreviousFailureTaskDefHash = if ($settings.Contains('B_PREVIOUS_FAILURE_TASKDEF_HASH')) { [string]$settings.B_PREVIOUS_FAILURE_TASKDEF_HASH } else { '' }
    $bFailureSourceHash = if ($settings.Contains('B_FAILURE_SOURCE_HASH')) { [string]$settings.B_FAILURE_SOURCE_HASH } else { '' }
    $bPreviousFailureSourceHash = if ($settings.Contains('B_PREVIOUS_FAILURE_SOURCE_HASH')) { [string]$settings.B_PREVIOUS_FAILURE_SOURCE_HASH } else { '' }
    $bFailureRoundImprintHash = if ($settings.Contains('B_FAILURE_TASKDEF_ROUND_IMPRINT_HASH')) { [string]$settings.B_FAILURE_TASKDEF_ROUND_IMPRINT_HASH } else { '' }
    $bPreviousFailureRoundImprintHash = if ($settings.Contains('B_PREVIOUS_FAILURE_TASKDEF_ROUND_IMPRINT_HASH')) { [string]$settings.B_PREVIOUS_FAILURE_TASKDEF_ROUND_IMPRINT_HASH } else { '' }

    $bRetryGrantKey = 'B_CODESTEP_IDENTICAL_FP_RETRY_GRANTED_FOR'
    $bRetryGrantAtKey = 'B_CODESTEP_IDENTICAL_FP_RETRY_GRANTED_AT'
    $bRetryCountKey = 'B_CODESTEP_IDENTICAL_FP_RETRY_COUNT'
    $bRetryStateKey = 'B_CODESTEP_IDENTICAL_FP_STATE'
    $bRetryStateAtKey = 'B_CODESTEP_IDENTICAL_FP_STATE_AT'
    $bRetryMax = 3
    if ($settings.Contains('CODESTEP_IDENTICAL_FP_MAX_RETRIES')) {
        $parsedGlobalRetryMax = Get-ParsedPositiveInt -Value ([string]$settings.CODESTEP_IDENTICAL_FP_MAX_RETRIES)
        if ($parsedGlobalRetryMax -gt 0) { $bRetryMax = $parsedGlobalRetryMax }
    }
    if ($settings.Contains('B_CODESTEP_IDENTICAL_FP_MAX_RETRIES')) {
        $parsedStageRetryMax = Get-ParsedPositiveInt -Value ([string]$settings.B_CODESTEP_IDENTICAL_FP_MAX_RETRIES)
        if ($parsedStageRetryMax -gt 0) { $bRetryMax = $parsedStageRetryMax }
    }

    if (-not [string]::IsNullOrWhiteSpace($bFailureTaskStartAt) -and
        -not [string]::IsNullOrWhiteSpace($bPreviousFailureTaskStartAt) -and
        $bFailureTaskStartAt -ne '-' -and
        $bPreviousFailureTaskStartAt -ne '-' -and
        $bFailureTaskStartAt -ne $bPreviousFailureTaskStartAt) {
        Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
            $bRetryGrantKey = ''
            $bRetryGrantAtKey = ''
            $bRetryCountKey = '0'
            $bRetryStateKey = ''
            $bRetryStateAtKey = ''
        }
        Write-Output ("[OPEN-AB-STAGE] identical_fp_retry_reset stage=B reason=task_start_window_changed previous={0} current={1}" -f $bPreviousFailureTaskStartAt, $bFailureTaskStartAt)
    }
    $bSameTaskStartWindow = $true
    if (-not [string]::IsNullOrWhiteSpace($bFailureTaskStartAt) -and
        -not [string]::IsNullOrWhiteSpace($bPreviousFailureTaskStartAt) -and
        $bFailureTaskStartAt -ne '-' -and
        $bPreviousFailureTaskStartAt -ne '-') {
        $bSameTaskStartWindow = ($bFailureTaskStartAt -eq $bPreviousFailureTaskStartAt)
    }

    if (-not [string]::IsNullOrWhiteSpace($bFailureMainRound) -and
        -not [string]::IsNullOrWhiteSpace($bPreviousFailureMainRound) -and
        $bFailureMainRound -eq $bPreviousFailureMainRound -and
        -not [string]::IsNullOrWhiteSpace($bFailurePhase) -and
        -not [string]::IsNullOrWhiteSpace($bPreviousFailurePhase) -and
        $bFailurePhase -eq $bPreviousFailurePhase -and
        $bSameTaskStartWindow -and
        -not [string]::IsNullOrWhiteSpace($bFailureFingerprint) -and
        -not [string]::IsNullOrWhiteSpace($bPreviousFailureFingerprint) -and
        $bFailureFingerprint -eq $bPreviousFailureFingerprint) {

        $bRetryCount = 0
        if ($settings.Contains($bRetryCountKey)) {
            $bRetryCount = Get-ParsedPositiveInt -Value ([string]$settings[$bRetryCountKey])
        }
        $bTaskDefChanged = (-not [string]::IsNullOrWhiteSpace($bFailureTaskDefHash) -and -not [string]::IsNullOrWhiteSpace($bPreviousFailureTaskDefHash) -and $bFailureTaskDefHash -ne '-' -and $bPreviousFailureTaskDefHash -ne '-' -and $bFailureTaskDefHash -ne $bPreviousFailureTaskDefHash)
        $bSourceChanged = (-not [string]::IsNullOrWhiteSpace($bFailureSourceHash) -and -not [string]::IsNullOrWhiteSpace($bPreviousFailureSourceHash) -and $bFailureSourceHash -ne '-' -and $bPreviousFailureSourceHash -ne '-' -and $bFailureSourceHash -ne $bPreviousFailureSourceHash)
        $bImprintChanged = (-not [string]::IsNullOrWhiteSpace($bFailureRoundImprintHash) -and -not [string]::IsNullOrWhiteSpace($bPreviousFailureRoundImprintHash) -and $bFailureRoundImprintHash -ne '-' -and $bPreviousFailureRoundImprintHash -ne '-' -and $bFailureRoundImprintHash -ne $bPreviousFailureRoundImprintHash)
        $bCurrentEvidence = Get-TaskDefinitionRepairEvidence -TaskDefinitionPath $taskDefinitionRelative -Round $bFailureMainRound
        $bCurrentTaskDefChanged = (-not [string]::IsNullOrWhiteSpace($bFailureTaskDefHash) -and $bFailureTaskDefHash -ne '-' -and -not [string]::IsNullOrWhiteSpace([string]$bCurrentEvidence.FileHash) -and [string]$bCurrentEvidence.FileHash -ne $bFailureTaskDefHash)
        $bCurrentImprintChanged = (-not [string]::IsNullOrWhiteSpace($bFailureRoundImprintHash) -and $bFailureRoundImprintHash -ne '-' -and -not [string]::IsNullOrWhiteSpace([string]$bCurrentEvidence.RoundImprintHash) -and [string]$bCurrentEvidence.RoundImprintHash -ne $bFailureRoundImprintHash)
        $bHasRepairEvidence = ($bTaskDefChanged -or $bSourceChanged -or $bImprintChanged -or $bCurrentTaskDefChanged -or $bCurrentImprintChanged)
        $bCurrentState = if ($settings.Contains($bRetryStateKey)) { (Convert-ToSingleLineText -Text ([string]$settings[$bRetryStateKey])).ToLowerInvariant() } else { '' }

        if ($bFailurePhase -eq 'code-step' -and $bCurrentState -eq 'hard_block' -and $bHasRepairEvidence) {
            Write-Output ("[OPEN-AB-STAGE] identical_fp_state_unlock stage=B reason=repair_evidence_detected round={0} task_start_at={1}" -f $bFailureMainRound, $bFailureTaskStartAt)
            $bRetryCount = 0
            $bCurrentState = ''
            Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
                $bRetryCountKey = '0'
                $bRetryStateKey = 'pending_review'
                $bRetryStateAtKey = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
            }
        }

        if ($bFailurePhase -eq 'code-step' -and $bRetryCount -lt $bRetryMax) {
            $bNextAttempt = $bRetryCount + 1
            if ($bNextAttempt -gt 1 -and -not $bHasRepairEvidence) {
                Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
                    $bRetryStateKey = 'hard_block'
                    $bRetryStateAtKey = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
                }
                Add-StageTaskDefinitionBlockedTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount $bNextAttempt -MaxFails $bRetryMax -PrecheckExitCode 0 -BlockEvent 'manual-wait-paused' -ExtraDetail ("fingerprint_duplicate=true retry_budget_exhausted=true retry_requires_evidence=true retry_count={0} retry_limit={1} round={2} phase={3} task_start_at={4} fingerprint={5}" -f $bRetryCount, $bRetryMax, $bFailureMainRound, $bFailurePhase, $bFailureTaskStartAt, $bFailureFingerprint) -RecommendedActionOverride 'Identical fingerprint retried without effective repair evidence. AI must change repair method (not same patch shape), adjust round operations/anchors, and produce evidence-changing edits before relaunch. Stop auto-retry, perform manual task-definition fix, pass static check, then relaunch.' -FailureCategoryOverride 'fingerprint-duplicate-manual-escalation' -FailureKindOverride 'fingerprint-duplicate-evidence-missing'
                throw ("[OPEN-AB-STAGE] infinite-loop-protection: B identical code-step fingerprint detected without repair evidence (round={0}, task_start_at={1}, fingerprint={2}). Manual intervention required." -f $bFailureMainRound, $bFailureTaskStartAt, $bFailureFingerprint)
            }

            $bRetryGrantedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
            Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
                $bRetryGrantKey = $bFailureFingerprint
                $bRetryGrantAtKey = $bRetryGrantedAt
                $bRetryCountKey = [string]$bNextAttempt
                $bRetryStateKey = 'override_window'
                $bRetryStateAtKey = $bRetryGrantedAt
            }
            Add-StageTaskDefinitionFixTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount $bNextAttempt -MaxFails $bRetryMax -PrecheckExitCode 0 -MainRound $bFailureMainRound -FailurePhase $bFailurePhase -FailureFingerprint $bFailureFingerprint -TaskStartAt $bFailureTaskStartAt -RetryAttempt $bNextAttempt -RetryMax $bRetryMax
            throw ("[OPEN-AB-STAGE] infinite-loop-protection: B identical code-step fingerprint detected (main_round={0}, phase={1}, task_start_at={2}, fingerprint={3}). Retry granted {4}/{5}; apply task-definition fix and relaunch." -f $bFailureMainRound, $bFailurePhase, $bFailureTaskStartAt, $bFailureFingerprint, $bNextAttempt, $bRetryMax)
        }

        if ($bFailurePhase -eq 'code-step') {
            Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values @{
                $bRetryStateKey = 'hard_block'
                $bRetryStateAtKey = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
            }
            Add-StageTaskDefinitionBlockedTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount ($bRetryCount + 1) -MaxFails $bRetryMax -PrecheckExitCode 0 -BlockEvent 'manual-wait-paused' -ExtraDetail ("fingerprint_duplicate=true retry_budget_exhausted=true retry_count={0} retry_limit={1} round={2} phase={3} task_start_at={4} fingerprint={5}" -f $bRetryCount, $bRetryMax, $bFailureMainRound, $bFailurePhase, $bFailureTaskStartAt, $bFailureFingerprint) -RecommendedActionOverride 'Fingerprint duplicate repeated after retry budget exhaustion. AI must switch to a different fix strategy (e.g., rewrite round op anchors/ordering or append-mode patch) instead of repeating prior edits. Stop auto self-heal and transfer to manual intervention only.' -FailureCategoryOverride 'fingerprint-duplicate-manual-escalation' -FailureKindOverride 'fingerprint-duplicate-retry-exhausted'
        }

        throw ("[OPEN-AB-STAGE] infinite-loop-protection: B failed repeatedly with identical fingerprint (main_round={0}, phase={1}, task_start_at={2}, fingerprint={3}). Retry budget exhausted; manual intervention required." -f $bFailureMainRound, $bFailurePhase, $bFailureTaskStartAt, $bFailureFingerprint)
    }
}

Write-Output ("[OPEN-AB-STAGE] launch_banner stage={0} start_file={1} start_monitors={2} skip_monitor_restart={3} b_restart_hint={4}" -f
    $Stage,
    $StartFile,
    [string]$StartMonitors.IsPresent,
    [string]$SkipMonitorRestart.IsPresent,
    [string]$EnableBMonitorRestart.IsPresent)

$stageRuntimeLogPath = ''
if ($Stage -eq 'B') {
    $runtimeLogRoot = Join-Path $repoRoot 'out\artifacts\ab_stage_runtime\B'
    if (-not (Test-Path -LiteralPath $runtimeLogRoot)) {
        New-Item -ItemType Directory -Path $runtimeLogRoot -Force | Out-Null
    }

    $runtimeStamp = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
    $stageRuntimeLogPath = Join-Path $runtimeLogRoot ("b_runtime_{0}.log" -f $runtimeStamp)
    Set-Item -Path 'Env:AUTO_STAGE_RUNTIME_LOG_PATH' -Value $stageRuntimeLogPath
}
else {
    Remove-Item -Path 'Env:AUTO_STAGE_RUNTIME_LOG_PATH' -ErrorAction SilentlyContinue
}

Set-Item -Path 'Env:AUTO_START_FILE_PATH' -Value $startFilePath

$autoStartMonitorsPlanned = $false
if ($Stage -eq 'A') {
    $autoStartMonitorsPlanned = if ($StartMonitors.IsPresent) {
        $true
    }
    elseif ($settings.Contains('AUTO_START_MONITORS')) {
        Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_MONITORS) -Default $false
    }
    else {
        $false
    }
}
elseif ($EnableBMonitorRestart.IsPresent) {
    $autoStartMonitorsPlanned = $true
}
elseif ($Stage -eq 'B') {
    $autoStartMonitorsPlanned = if ($settings.Contains('AUTO_START_MONITORS')) {
        Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_MONITORS) -Default $true
    }
    else {
        $true
    }
}

$monitorBootstrapGateFile = ''
if ($autoStartMonitorsPlanned) {
    $gateDir = Join-Path $repoRoot 'out\artifacts\ab_monitor_gate'
    if (-not (Test-Path -LiteralPath $gateDir)) {
        New-Item -ItemType Directory -Path $gateDir -Force | Out-Null
    }

    $gateStamp = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
    $monitorBootstrapGateFile = Join-Path $gateDir ("monitor_bootstrap_gate_{0}_{1}.json" -f $Stage.ToLowerInvariant(), $gateStamp)
    $gateSeed = [pscustomobject]@{
        schema = 'AB_MONITOR_BOOTSTRAP_GATE_V1'
        status = 'pending'
        stage = $Stage
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        reason = 'waiting-monitor-bootstrap-gate'
    }
    [System.IO.File]::WriteAllText($monitorBootstrapGateFile, ($gateSeed | ConvertTo-Json -Depth 4), [System.Text.UTF8Encoding]::new($false))
    Set-Item -Path 'Env:AUTO_MONITOR_BOOTSTRAP_GATE_FILE' -Value $monitorBootstrapGateFile

    $gateWaitSec = 120
    if ($settings.Contains('MONITOR_FIRST_BOOTSTRAP_TIMEOUT_SEC')) {
        $parsedGateWaitSec = 0
        if ([int]::TryParse(([string]$settings.MONITOR_FIRST_BOOTSTRAP_TIMEOUT_SEC), [ref]$parsedGateWaitSec)) {
            if ($parsedGateWaitSec -ge 10 -and $parsedGateWaitSec -le 1800) {
                $gateWaitSec = $parsedGateWaitSec
            }
        }
    }
    Set-Item -Path 'Env:AUTO_MONITOR_BOOTSTRAP_GATE_MAX_WAIT_SEC' -Value ([string]([Math]::Max(60, $gateWaitSec + 30)))
}
else {
    Remove-Item -Path 'Env:AUTO_MONITOR_BOOTSTRAP_GATE_FILE' -ErrorAction SilentlyContinue
    Remove-Item -Path 'Env:AUTO_MONITOR_BOOTSTRAP_GATE_MAX_WAIT_SEC' -ErrorAction SilentlyContinue
}

$keepWindowOnExit = if ($settings.Contains('KEEP_WINDOW_ON_EXIT')) {
    Convert-ToBooleanSetting -Value ([string]$settings.KEEP_WINDOW_ON_EXIT) -Default $true
}
else {
    $true
}

$stageLaunchTime = Get-Date
$stageArgumentList = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $entryScriptPath,
    $taskDefinitionRelative
)
if ($keepWindowOnExit) {
    $stageArgumentList = @('-NoExit') + $stageArgumentList
}

$stageLaunchProbeDelayMs = 1200
if ($settings.Contains('STAGE_LAUNCH_PROBE_DELAY_MS')) {
    $parsedProbeDelayMs = 0
    if ([int]::TryParse(([string]$settings.STAGE_LAUNCH_PROBE_DELAY_MS), [ref]$parsedProbeDelayMs)) {
        if ($parsedProbeDelayMs -ge 0 -and $parsedProbeDelayMs -le 10000) {
            $stageLaunchProbeDelayMs = $parsedProbeDelayMs
        }
    }
}

$stageAliveAfterProbe = $false
$launchRetryAttempt = 0
$launchMaxRetries = 3
while (-not $stageAliveAfterProbe -and $launchRetryAttempt -lt $launchMaxRetries) {
    if ($launchRetryAttempt -gt 0) {
        Write-Output ("[OPEN-AB-STAGE] launch_retry stage={0} attempt={1}/{2}" -f $Stage, ($launchRetryAttempt + 1), $launchMaxRetries)
        Start-Sleep -Milliseconds 500
    }
    $launchRetryAttempt++

    # ── Clean up orphan window from a prior retry if it somehow ghosted ──
    $priorAlive = $false
    try { $priorAlive = ($null -ne (Get-Variable -Name 'processInfo' -ErrorAction Stop) -and $null -ne $processInfo -and (Test-ProcessAlive -ProcessId ([int]$processInfo.Id))) } catch { $priorAlive = $false }
    if ($priorAlive) {
        Write-Output ("[OPEN-AB-STAGE] clean_orphan_retry_proc pid={0}" -f $processInfo.Id)
        Stop-Process -Id ([int]$processInfo.Id) -Force -ErrorAction SilentlyContinue
    }

    $processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $stageArgumentList -PassThru

    Write-Output ("[OPEN-AB-STAGE] stage={0} pid={1} launcher_pid={2} entry={3} task={4}" -f $Stage, $processInfo.Id, $PID, $entryScriptPath, $taskDefinitionRelative)
    if ($Stage -eq 'B' -and -not [string]::IsNullOrWhiteSpace($stageRuntimeLogPath)) {
        Write-Output ("[OPEN-AB-STAGE] runtime_log={0}" -f (Convert-ToAnchorPath -Path $stageRuntimeLogPath))
    }

    if ($stageLaunchProbeDelayMs -gt 0) {
        Start-Sleep -Milliseconds $stageLaunchProbeDelayMs
    }

    $stageAliveAfterProbe = Test-ProcessAlive -ProcessId ([int]$processInfo.Id)
}

if (-not $stageAliveAfterProbe) {
    $failureDetail = ("stage={0} pid={1} exited_during_launch_probe delay_ms={2}" -f $Stage, $processInfo.Id, $stageLaunchProbeDelayMs)
    $failureNotes = "stage_launch_fail $failureDetail"
    $failUpdates = @{
        SESSION_FINAL_STATUS = 'FAIL'
        SESSION_FINAL_NOTES = ''
    }

    if ($Stage -eq 'A') {
        $failUpdates['A_FINAL_STATUS'] = 'FAIL'
        if ($settings.Contains('B_FINAL_STATUS') -and [string]$settings.B_FINAL_STATUS -eq 'NOT_RUN') {
            $failUpdates['B_FINAL_STATUS'] = 'BLOCKED'
        }
        $failUpdates['A_LAUNCH_PID'] = '0'
    }
    else {
        $failUpdates['B_FINAL_STATUS'] = 'FAIL'
        $failUpdates['B_LAUNCH_PID'] = '0'
    }

    if ($settings.Contains('SESSION_FINAL_NOTES') -and -not [string]::IsNullOrWhiteSpace([string]$settings.SESSION_FINAL_NOTES)) {
        $failUpdates['SESSION_FINAL_NOTES'] = ([string]$settings.SESSION_FINAL_NOTES + '; ' + $failureNotes)
    }
    else {
        $failUpdates['SESSION_FINAL_NOTES'] = $failureNotes
    }

    Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values $failUpdates
    Write-Output ("[OPEN-AB-STAGE] stage_launch_fail {0}" -f $failureDetail)
    Write-Output "[OPEN-AB-STAGE] monitor_anchor_preserved reason=launch_probe_failed"
    exit 1
}

$statusUpdates = @{
    SESSION_FINAL_STATUS = 'RUNNING'
    SESSION_CLOSED = 'false'
    SESSION_CLOSED_AT = ''
    SESSION_CLOSED_REASON = ''
}
# Record session initial launch timestamp (only set once, never overwritten)
if ([string]::IsNullOrWhiteSpace($settings['SESSION_INITIAL_LAUNCH_AT'])) {
    $statusUpdates['SESSION_INITIAL_LAUNCH_AT'] = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}
if ($Stage -eq 'A') {
    $statusUpdates['A_FINAL_STATUS'] = 'RUNNING'
    $statusUpdates['A_LAUNCH_PID'] = [string]$processInfo.Id
}
else {
    $statusUpdates['B_FINAL_STATUS'] = 'RUNNING'
    $statusUpdates['B_LAUNCH_PID'] = [string]$processInfo.Id
    $statusUpdates['AB_HANDOVER_STATE'] = 'A_TO_B_COMPLETE'
    $statusUpdates['AB_HANDOVER_COMPLETED_AT'] = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $statusUpdates['AB_HANDOVER_COMPLETED_BY'] = 'open_unattended_ab_stage_window.ps1'
    if (-not [string]::IsNullOrWhiteSpace($stageRuntimeLogPath)) {
        $statusUpdates['B_RUNTIME_LOG'] = Convert-ToAnchorPath -Path $stageRuntimeLogPath
    }
}
Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values $statusUpdates
$settings = Read-KeyValueFile -Path $startFilePath
Write-Output ("[OPEN-AB-STAGE] stage_status_update stage={0} session_status=RUNNING" -f $Stage)

$autoStartMonitors = $autoStartMonitorsPlanned

if (-not $autoStartMonitors) {
    exit 0
}

$sessionOutDirRoot = Join-Path $repoRoot 'out\artifacts\dev_verify_multiround'
$currentStageRunDir = Resolve-CurrentStageRunDir -LaunchTime $stageLaunchTime -Settings $settings -SessionOutDirRoot $sessionOutDirRoot -StageProcessId ([int]$processInfo.Id)
if (-not [string]::IsNullOrWhiteSpace($currentStageRunDir)) {
    $updatedNotes = Invoke-SessionAnchorUpdateInStartFile -Path $startFilePath -Anchors @{ run_dir = (Convert-ToAnchorPath -Path $currentStageRunDir) }
    Write-Output ("[OPEN-AB-STAGE] anchor_update run_dir={0}" -f (Convert-ToAnchorPath -Path $currentStageRunDir))
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'run_dir_anchor_update' -Fields @{ stage = $Stage; run_dir = (Convert-ToAnchorPath -Path $currentStageRunDir) }
    $settings = Read-KeyValueFile -Path $startFilePath
}
else {
    Write-Output '[OPEN-AB-STAGE] anchor_update run_dir=unknown'
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'run_dir_anchor_update' -Fields @{ stage = $Stage; run_dir = 'unknown' }
}

$bRestartMode = $bRestartModeForGate
$bForceMonitorRestart = ($Stage -eq 'B' -and $EnableBMonitorRestart.IsPresent)
if ($bRestartMode) {
    $monitorRestartPolicy = if ($bForceMonitorRestart) { 'force-full-restart' } else { 'rebind-existing' }
    Write-Output ("[OPEN-AB-STAGE] b_restart_mode=true monitor_restart_policy={0}" -f $monitorRestartPolicy)
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'b_restart_mode' -Fields @{
        stage = $Stage
        monitor_restart_policy = $monitorRestartPolicy
        force_monitor_restart = [bool]$bForceMonitorRestart
    }
}

$skipMonitorRestart = $SkipMonitorRestart.IsPresent
if ($skipMonitorRestart -and $Stage -eq 'B') {
    Write-Output '[OPEN-AB-STAGE] monitor_restart_skip_ignored stage=B reason=monitor-policy-enforced'
    $skipMonitorRestart = $false
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'stage_launch' -Fields @{
        stage = $Stage
        stage_pid = [int]$processInfo.Id
        launcher_pid = [int]$PID
        entry = (Convert-ToAnchorPath -Path $entryScriptPath)
        task = $taskDefinitionRelative
    }
}

$monitorReuseMaxStaleMinutes = Get-MonitorReuseStaleMinutes -Settings $settings
$monitorReuseUnanchored = $false
$monitorStates = $null

if (-not $bForceMonitorRestart -and -not $skipMonitorRestart) {
    $monitorPresenceProbe = Test-MonitorReuseProcessPresence -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorReuseProbe = Test-MonitorReuseActivity -Settings $settings -RepoRoot $repoRoot -MaxStaleMinutes $monitorReuseMaxStaleMinutes
    if (-not [bool]$monitorPresenceProbe.Active -and -not [bool]$monitorReuseProbe.Active) {
        # STALE: no process presence and no recent anchor activity.
        # Do NOT stop old monitor processes — guard/trigger self-manage.  Just signal fresh-launch needed.
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse_guard status=STALE threshold_min={0} evidence={1} action=self-managed" -f [int]$monitorReuseProbe.ThresholdMinutes, (($monitorReuseProbe.Evidence -join ';')))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse_guard_stale' -Fields @{
            stage = $Stage
            threshold_min = [int]$monitorReuseProbe.ThresholdMinutes
            evidence = @($monitorReuseProbe.Evidence)
        }

        if (-not $bForceMonitorRestart) {
            $monitorStates = @{}
        }
    }
    elseif ([bool]$monitorPresenceProbe.Active -and -not [bool]$monitorReuseProbe.Active) {
        # ACTIVE-UNANCHORED: process presence found but no recent anchor activity.
        # Monitors are alive but tied to a stale (previous-run) main process.
        # Set unanchored flag so the probe below forces fresh launch instead of reusing
        # stale processes that still reference the old run_dir / PID.
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse_guard status=ACTIVE-UNANCHORED match_count={0} evidence={1} action=self-managed" -f [int]$monitorPresenceProbe.MatchCount, (($monitorPresenceProbe.Evidence -join ';')))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse_guard_stale' -Fields @{
            stage = $Stage
            threshold_min = [int]$monitorReuseProbe.ThresholdMinutes
            evidence = @($monitorReuseProbe.Evidence)
        }
        $monitorReuseUnanchored = $true
        $monitorStates = @{}
    }
    else {
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse_guard status=ACTIVE threshold_min={0} evidence={1}" -f [int]$monitorReuseProbe.ThresholdMinutes, (($monitorReuseProbe.Evidence -join ';')))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse_guard_active' -Fields @{
            stage = $Stage
            threshold_min = [int]$monitorReuseProbe.ThresholdMinutes
            evidence = @($monitorReuseProbe.Evidence)
        }
    }
}

# Per-role stale cleanup and B-force-restart stop are intentionally removed.
# All monitor chain processes self-manage:
#   guard/trigger — detect stale state and exit, or bind to new main process

$guardLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_GUARD') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_GUARD)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_GUARD
}
else {
    'tools/test/open_unattended_ab_session_guard_window.ps1'
}

$guardLauncherPath = Resolve-RepoPath -Path $guardLauncherRelative

$triggerLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_TRIGGER') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_TRIGGER)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_TRIGGER
}
else {
    'tools/test/open_unattended_ab_takeover_trigger_window.ps1'
}

$triggerLauncherPath = Resolve-RepoPath -Path $triggerLauncherRelative

$autoStartTakeoverTrigger = if ($settings.Contains('AUTO_START_TAKEOVER_TRIGGER')) {
    Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_TAKEOVER_TRIGGER) -Default $false
}
elseif ($settings.Contains('EXTERNAL_TRIGGER_EXECUTE')) {
    Convert-ToBooleanSetting -Value ([string]$settings.EXTERNAL_TRIGGER_EXECUTE) -Default $false
}
else {
    $false
}

$monitorStates = @{}
if (-not $bForceMonitorRestart) {
    $monitorStates.guard = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_session_guard.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorStates.trigger = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_takeover_trigger.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot

    # Verify matched processes are truly alive (not empty shells).
    # Zombie processes have matching command lines but the script has terminated.
    # If a zombie is found, clear its binding so the launcher will kill it and start fresh.
    $zombieCheckRoles = @('guard', 'trigger')
    foreach ($zRole in $zombieCheckRoles) {
        if (-not $monitorStates.ContainsKey($zRole)) { continue }
        $state = $monitorStates[$zRole]
        if (-not [bool]$state.RunningForStartFile) { continue }

        $trulyAlive = Test-RoleProcessTrulyAlive -Role $zRole -Processes @($state.MatchPids | ForEach-Object {
            $zp = $_
            try {
                $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$zp" -ErrorAction SilentlyContinue
                if ($null -ne $proc) { $proc } else { $null }
            } catch { $null }
        }) -RepoRoot $repoRoot

        if (-not $trulyAlive) {
            Write-Output ("[OPEN-AB-STAGE] monitor_role_zombie_detected role={0} pids={1}" -f $zRole, ($state.MatchPids -join ','))
            # Kill zombie processes
            foreach ($zpid in @($state.MatchPids)) {
                try {
                    Stop-Process -Id $zpid -Force -ErrorAction SilentlyContinue
                    Write-Output ("[OPEN-AB-STAGE] monitor_role_zombie_killed role={0} pid={1}" -f $zRole, $zpid)
                }
                catch {
                    Write-Output ("[OPEN-AB-STAGE] monitor_role_zombie_kill_failed role={0} pid={1}" -f $zRole, $zpid)
                }
            }
            # Clear binding state to force fresh launch
            $state | Add-Member -MemberType NoteProperty -Name 'RunningForStartFile' -Value $false -Force
            $state | Add-Member -MemberType NoteProperty -Name 'MatchCount' -Value 0 -Force
            $state | Add-Member -MemberType NoteProperty -Name 'MatchPids' -Value @() -Force
        }
    }

    $requiredMonitorRoles = @('guard')
    if ($autoStartTakeoverTrigger) {
        $requiredMonitorRoles += 'trigger'
    }

    if ($Stage -eq 'B' -and -not [bool]$monitorStates.guard.RunningForStartFile) {
        $parentGuardEvidence = Get-ParentMonitorBindingEvidence -ScriptLeaf 'unattended_ab_session_guard.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
        if ([bool]$parentGuardEvidence.Matches) {
            $monitorStates.guard | Add-Member -MemberType NoteProperty -Name 'RunningForStartFile' -Value $true -Force
            $monitorStates.guard | Add-Member -MemberType NoteProperty -Name 'MatchCount' -Value 1 -Force
            $monitorStates.guard | Add-Member -MemberType NoteProperty -Name 'MatchPids' -Value @([int]$parentGuardEvidence.ProcessId) -Force
            Write-Output ('[OPEN-AB-STAGE] monitor_parent_reuse role=guard stage=B pid={0}' -f [int]$parentGuardEvidence.ProcessId)
            Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_parent_reuse' -Fields @{ stage = $Stage; role = 'guard'; pid = [int]$parentGuardEvidence.ProcessId }
        }
    }

    $missingMonitorRoles = @()
    foreach ($role in $requiredMonitorRoles) {
        if (-not $monitorStates.ContainsKey($role) -or -not [bool]$monitorStates[$role].RunningForStartFile) {
            $missingMonitorRoles += $role
        }
    }

    if ($missingMonitorRoles.Count -eq 0) {
        if ($monitorReuseUnanchored) {
            # ACTIVE-UNANCHORED: monitor processes are alive but bound to a stale
            # (previous-run) main process.  Do NOT force-launch — all monitor roles
            # self-manage anchor rebinding:
            #   guard/trigger — read A_LAUNCH_PID / B_LAUNCH_PID from start-file
            #                   each cycle and auto-rebind on change.
            # Force-launching them is both unnecessary and harmful (e.g. guard
            # mid-grace restarts lose continuity).  Just log and reuse.
            Write-Output ("[OPEN-AB-STAGE] monitor_chain_probe status=ALL-REAL-LIVE-BUT-UNANCHORED roles={0} action=self-managed-reuse" -f ($requiredMonitorRoles -join ','))
            Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_chain_probe_unanchored' -Fields @{ stage = $Stage; roles = @($requiredMonitorRoles); action = 'self-managed-reuse' }
        }
        else {
            Write-Output ("[OPEN-AB-STAGE] monitor_chain_probe status=ALL-REAL-LIVE roles={0} action=reuse" -f ($requiredMonitorRoles -join ','))
            Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_chain_probe_all_live' -Fields @{ stage = $Stage; roles = @($requiredMonitorRoles) }
        }
    }
    else {
        Write-Output ("[OPEN-AB-STAGE] monitor_chain_probe status=PARTIAL-OR-MISSING required={0} missing={1} action=launch-missing" -f ($requiredMonitorRoles -join ','), ($missingMonitorRoles -join ','))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_chain_probe_partial' -Fields @{ stage = $Stage; required = @($requiredMonitorRoles); missing = @($missingMonitorRoles) }
    }

}

function Get-RestartReasonFromState {
    param([object]$State)

    if ($null -eq $State) {
        return 'state-unknown'
    }

    if ([int]$State.TotalCount -eq 0) {
        return 'not-running'
    }

    if ([int]$State.MatchCount -eq 0) {
        return 'binding-mismatch'
    }

    return 'healthy'
}

function Test-ShouldRestartMonitorRole {
    param(
        [string]$Role,
        [bool]$ForceRestart,
        [bool]$SkipRestart,
        [hashtable]$States
    )

    if ($SkipRestart) {
        return $false
    }

    if ($ForceRestart) {
        return $true
    }

    if ($null -eq $States -or -not $States.ContainsKey($Role)) {
        return $true
    }

    return (-not [bool]$States[$Role].RunningForStartFile)
}

function Get-BooleanSettingOrDefault {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key,
        [bool]$Default
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key) -or -not $Settings.Contains($Key)) {
        return $Default
    }

    return (Convert-ToBooleanSetting -Value ([string]$Settings[$Key]) -Default $Default)
}

function Get-IntSettingOrDefault {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key,
        [int]$Default,
        [int]$Min = 1,
        [int]$Max = 3600
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key) -or -not $Settings.Contains($Key)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse(([string]$Settings[$Key]), [ref]$parsed)) {
        return $Default
    }
    if ($parsed -lt $Min -or $parsed -gt $Max) {
        return $Default
    }

    return [int]$parsed
}

function Invoke-MonitorLauncherScript {
    param(
        [Parameter(Mandatory = $true)][string]$LauncherPath,
        [Parameter(Mandatory = $true)][string]$StartFilePath,
        [switch]$NoRestartIfRunning
    )

    $launcherArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $LauncherPath,
        '-StartFile', $StartFilePath
    )

    if ($NoRestartIfRunning.IsPresent) {
        $launcherArgs += '-NoRestartIfRunning'
    }

    $outputLines = @(& $powershellPath @launcherArgs 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines = @($outputLines)
    }
}

function Get-MonitorRoleReadiness {
    param(
        [ValidateSet('guard', 'trigger')][string]$Role,
        [string]$StartFilePath,
        [string]$RepoRoot,
        [string]$ScriptLeaf
    )

    $state = Get-MonitorBindingState -ScriptLeaf $ScriptLeaf -StartFilePath $StartFilePath -RepoRoot $RepoRoot
    $isReady = $false
    $isZombie = $false
    $evidence = 'not-running-for-start-file'

    if ([bool]$state.RunningForStartFile -and @($state.MatchPids).Count -gt 0) {
        $procObjects = @($state.MatchPids | ForEach-Object {
            $matchPid = [int]$_
            try { Get-CimInstance Win32_Process -Filter "ProcessId=$matchPid" -ErrorAction SilentlyContinue } catch { $null }
        } | Where-Object { $null -ne $_ })

        $trulyAlive = Test-RoleProcessTrulyAlive -Role $Role -Processes $procObjects -RepoRoot $RepoRoot
        if ($trulyAlive) {
            $isReady = $true
            $evidence = ('running match_count={0} pids={1}' -f [int]$state.MatchCount, (@($state.MatchPids) -join ','))
        }
        else {
            $isZombie = $true
            $evidence = ('zombie-shell match_count={0} pids={1}' -f [int]$state.MatchCount, (@($state.MatchPids) -join ','))
        }
    }

    return [pscustomobject]@{
        Role = $Role
        State = $state
        Ready = [bool]$isReady
        Zombie = [bool]$isZombie
        Evidence = $evidence
    }
}

function Invoke-MonitorFirstBootstrapBlockingGate {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [string]$StartFilePath,
        [string]$RepoRoot,
        [string]$TimelinePath,
        [bool]$AutoStartTakeoverTrigger,
        [string]$GuardLauncherPath,
        [string]$TriggerLauncherPath,
        [pscustomobject]$GuardStateAtGateBegin,
        [pscustomobject]$TriggerStateAtGateBegin
    )

    $gateSettings = Read-KeyValueFile -Path $StartFilePath
    $gateEnabled = Get-BooleanSettingOrDefault -Settings $gateSettings -Key 'MONITOR_FIRST_BOOTSTRAP_BLOCKING_ENABLED' -Default $true
    if (-not $gateEnabled) {
        Write-Output ('[OPEN-AB-STAGE] monitor_bootstrap_gate skip reason=disabled stage={0}' -f $Stage)
        Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_skipped' -Fields @{ stage = $Stage; reason = 'disabled' }
        return
    }

    $timeoutSec = Get-IntSettingOrDefault -Settings $gateSettings -Key 'MONITOR_FIRST_BOOTSTRAP_TIMEOUT_SEC' -Default 120 -Min 10 -Max 1800
    $pollSec = Get-IntSettingOrDefault -Settings $gateSettings -Key 'MONITOR_FIRST_BOOTSTRAP_POLL_SEC' -Default 3 -Min 1 -Max 30
    $maxRepairAttemptsPerRole = Get-IntSettingOrDefault -Settings $gateSettings -Key 'MONITOR_FIRST_BOOTSTRAP_MAX_REPAIR_PER_ROLE' -Default 1 -Min 0 -Max 5
    $failClose = Get-BooleanSettingOrDefault -Settings $gateSettings -Key 'MONITOR_FIRST_BOOTSTRAP_FAIL_CLOSE' -Default $false

    $guardStartedAsReuse = ($null -ne $GuardStateAtGateBegin -and [bool]$GuardStateAtGateBegin.RunningForStartFile)
    $triggerStartedAsReuse = ($null -ne $TriggerStateAtGateBegin -and [bool]$TriggerStateAtGateBegin.RunningForStartFile)

    $repairAttempts = @{ guard = 0; trigger = 0 }
    $gateStart = Get-Date
    $deadline = $gateStart.AddSeconds($timeoutSec)
    $loopIndex = 0

    Write-Output ('[OPEN-AB-STAGE] monitor_bootstrap_gate begin stage={0} timeout_sec={1} poll_sec={2} trigger_required={3} fail_close={4}' -f $Stage, $timeoutSec, $pollSec, [string]$AutoStartTakeoverTrigger, [string]$failClose)
    Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_begin' -Fields @{ stage = $Stage; timeout_sec = $timeoutSec; poll_sec = $pollSec; trigger_required = [bool]$AutoStartTakeoverTrigger; fail_close = [bool]$failClose }

    while ((Get-Date) -lt $deadline) {
        $loopIndex++

        $guardReady = Get-MonitorRoleReadiness -Role 'guard' -StartFilePath $StartFilePath -RepoRoot $RepoRoot -ScriptLeaf 'unattended_ab_session_guard.ps1'
        $triggerReady = if ($AutoStartTakeoverTrigger) {
            Get-MonitorRoleReadiness -Role 'trigger' -StartFilePath $StartFilePath -RepoRoot $RepoRoot -ScriptLeaf 'unattended_ab_takeover_trigger.ps1'
        }
        else {
            [pscustomobject]@{ Ready = $true; Zombie = $false; Evidence = 'not-required'; State = $null }
        }

        if ([bool]$guardReady.Zombie -and @($guardReady.State.MatchPids).Count -gt 0) {
            $null = Stop-MonitorProcessGracefully -ProcessIds @($guardReady.State.MatchPids)
        }
        if ($AutoStartTakeoverTrigger -and [bool]$triggerReady.Zombie -and @($triggerReady.State.MatchPids).Count -gt 0) {
            $null = Stop-MonitorProcessGracefully -ProcessIds @($triggerReady.State.MatchPids)
        }

        if ([bool]$guardReady.Ready -and [bool]$triggerReady.Ready) {
            $guardMode = if ($guardStartedAsReuse) { 'reuse' } else { 'new' }
            $triggerMode = if (-not $AutoStartTakeoverTrigger) { 'not-required' } elseif ($triggerStartedAsReuse) { 'reuse' } else { 'new' }

            $recoverUpdates = @{
                MONITOR_CHAIN_DEGRADED = 'false'
                MONITOR_CHAIN_DEGRADED_REASON = ''
                MONITOR_CHAIN_DEGRADED_STAGE = ''
                MONITOR_CHAIN_DEGRADED_ROLES = ''
            }
            if ($gateSettings.Contains('MONITOR_CHAIN_DEGRADED') -and (Convert-ToBooleanSetting -Value ([string]$gateSettings.MONITOR_CHAIN_DEGRADED) -Default $false)) {
                $recoverUpdates['MONITOR_CHAIN_DEGRADED_RECOVERED_AT'] = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            }
            Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values $recoverUpdates

            Write-Output ('[OPEN-AB-STAGE] monitor_bootstrap_gate ready stage={0} guard_mode={1} trigger_mode={2} loops={3}' -f $Stage, $guardMode, $triggerMode, $loopIndex)
            Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_ready' -Fields @{ stage = $Stage; guard_mode = $guardMode; trigger_mode = $triggerMode; loops = $loopIndex; guard = [string]$guardReady.Evidence; trigger = [string]$triggerReady.Evidence }
            return
        }

        if (-not [bool]$guardReady.Ready -and [int]$repairAttempts.guard -lt $maxRepairAttemptsPerRole) {
            $repairAttempts.guard = [int]$repairAttempts.guard + 1
            try {
                $guardRepairResult = Invoke-MonitorLauncherScript -LauncherPath $GuardLauncherPath -StartFilePath $StartFilePath -NoRestartIfRunning
                foreach ($line in @($guardRepairResult.Lines)) {
                    if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Output $line }
                }
                if ([int]$guardRepairResult.ExitCode -ne 0) {
                    Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_repair_failed' -Fields @{ stage = $Stage; role = 'guard'; attempt = [int]$repairAttempts.guard; detail = ('launcher-exit-{0}' -f [int]$guardRepairResult.ExitCode) }
                }
                Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_repair' -Fields @{ stage = $Stage; role = 'guard'; attempt = [int]$repairAttempts.guard; action = 'launcher-invoke'; evidence = [string]$guardReady.Evidence }
            }
            catch {
                Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_repair_failed' -Fields @{ stage = $Stage; role = 'guard'; attempt = [int]$repairAttempts.guard; detail = (Convert-ToSingleLineText -Text $_.Exception.Message) }
            }
        }

        if ($AutoStartTakeoverTrigger -and -not [bool]$triggerReady.Ready -and [int]$repairAttempts.trigger -lt $maxRepairAttemptsPerRole) {
            $repairAttempts.trigger = [int]$repairAttempts.trigger + 1
            try {
                if (Test-Path -LiteralPath $TriggerLauncherPath) {
                    $triggerRepairResult = Invoke-MonitorLauncherScript -LauncherPath $TriggerLauncherPath -StartFilePath $StartFilePath -NoRestartIfRunning
                    foreach ($line in @($triggerRepairResult.Lines)) {
                        if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Output $line }
                    }
                    if ([int]$triggerRepairResult.ExitCode -ne 0) {
                        Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_repair_failed' -Fields @{ stage = $Stage; role = 'trigger'; attempt = [int]$repairAttempts.trigger; detail = ('launcher-exit-{0}' -f [int]$triggerRepairResult.ExitCode) }
                    }
                    Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_repair' -Fields @{ stage = $Stage; role = 'trigger'; attempt = [int]$repairAttempts.trigger; action = 'launcher-invoke'; evidence = [string]$triggerReady.Evidence }
                }
            }
            catch {
                Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_repair_failed' -Fields @{ stage = $Stage; role = 'trigger'; attempt = [int]$repairAttempts.trigger; detail = (Convert-ToSingleLineText -Text $_.Exception.Message) }
            }
        }

        $elapsedSec = [int][Math]::Floor(((Get-Date) - $gateStart).TotalSeconds)
        Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_progress' -Fields @{ stage = $Stage; elapsed_sec = $elapsedSec; guard_ready = [bool]$guardReady.Ready; trigger_ready = [bool]$triggerReady.Ready; guard_attempts = [int]$repairAttempts.guard; trigger_attempts = [int]$repairAttempts.trigger; guard_evidence = [string]$guardReady.Evidence; trigger_evidence = [string]$triggerReady.Evidence }

        Start-Sleep -Seconds $pollSec
    }

    $finalGuard = Get-MonitorRoleReadiness -Role 'guard' -StartFilePath $StartFilePath -RepoRoot $RepoRoot -ScriptLeaf 'unattended_ab_session_guard.ps1'
    $finalTrigger = if ($AutoStartTakeoverTrigger) {
        Get-MonitorRoleReadiness -Role 'trigger' -StartFilePath $StartFilePath -RepoRoot $RepoRoot -ScriptLeaf 'unattended_ab_takeover_trigger.ps1'
    }
    else {
        [pscustomobject]@{ Ready = $true; Evidence = 'not-required' }
    }

    $missingRoles = New-Object 'System.Collections.Generic.List[string]'
    if (-not [bool]$finalGuard.Ready) { [void]$missingRoles.Add('guard') }
    if ($AutoStartTakeoverTrigger -and -not [bool]$finalTrigger.Ready) { [void]$missingRoles.Add('trigger') }

    $degradedReason = ('monitor_bootstrap_timeout stage={0} missing={1} guard={2} trigger={3} attempts_guard={4} attempts_trigger={5}' -f $Stage, ($missingRoles -join ','), [string]$finalGuard.Evidence, [string]$finalTrigger.Evidence, [int]$repairAttempts.guard, [int]$repairAttempts.trigger)
    Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{
        MONITOR_CHAIN_DEGRADED = 'true'
        MONITOR_CHAIN_DEGRADED_AT = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        MONITOR_CHAIN_DEGRADED_STAGE = $Stage
        MONITOR_CHAIN_DEGRADED_REASON = (Convert-ToBoundedSingleLineText -Text $degradedReason -MaxChars 280)
        MONITOR_CHAIN_DEGRADED_ROLES = ($missingRoles -join ',')
    }

    Write-Output ('[OPEN-AB-STAGE] monitor_bootstrap_gate timeout stage={0} missing={1} action=degraded-continue fail_close={2}' -f $Stage, ($missingRoles -join ','), [string]$failClose)
    Write-MonitorTimelineEvent -TimelinePath $TimelinePath -EventName 'monitor_first_bootstrap_blocking_timeout' -Fields @{ stage = $Stage; missing = @($missingRoles); guard = [string]$finalGuard.Evidence; trigger = [string]$finalTrigger.Evidence; attempts_guard = [int]$repairAttempts.guard; attempts_trigger = [int]$repairAttempts.trigger; fail_close = [bool]$failClose }

    if ($failClose) {
        throw ('[OPEN-AB-STAGE] monitor bootstrap blocking gate failed (fail-close): {0}' -f $degradedReason)
    }
}

$restartGuard = Test-ShouldRestartMonitorRole -Role 'guard' -ForceRestart $bForceMonitorRestart -SkipRestart $skipMonitorRestart -States $monitorStates
if ($restartGuard) {
    if (-not $bForceMonitorRestart -and $monitorStates.ContainsKey('guard')) {
        $guardStateObj = $monitorStates.guard
        Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=guard reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
            (Get-RestartReasonFromState -State $guardStateObj),
            [int]$guardStateObj.MatchCount,
            [int]$guardStateObj.MismatchCount,
            [int]$guardStateObj.UnboundCount)
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_restart_single' -Fields @{ stage = $Stage; role = 'guard'; reason = (Get-RestartReasonFromState -State $guardStateObj); match_count = [int]$guardStateObj.MatchCount; mismatch_count = [int]$guardStateObj.MismatchCount; unbound_count = [int]$guardStateObj.UnboundCount }
    }

    $guardLaunchResult = Invoke-MonitorLauncherScript -LauncherPath $guardLauncherPath -StartFilePath $StartFile -NoRestartIfRunning
    $guardOutput = @($guardLaunchResult.Lines)
    $guardLog = ''
    foreach ($line in @($guardOutput | ForEach-Object { [string]$_ })) {
        Write-Output $line
        if ($line -match 'guard_log=([^\s]+)') {
            $guardLog = $Matches[1]
        }
    }
}
else {
    if ($monitorStates.ContainsKey('guard')) {
        $guardStateObj = $monitorStates.guard
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse role=guard match_count={0} mismatch_count={1} unbound_count={2} pids={3}" -f
            [int]$guardStateObj.MatchCount,
            [int]$guardStateObj.MismatchCount,
            [int]$guardStateObj.UnboundCount,
            ($guardStateObj.MatchPids -join ','))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse' -Fields @{ stage = $Stage; role = 'guard'; match_count = [int]$guardStateObj.MatchCount; mismatch_count = [int]$guardStateObj.MismatchCount; unbound_count = [int]$guardStateObj.UnboundCount; pids = @($guardStateObj.MatchPids) }
    }

    $guardLaunchResult = Invoke-MonitorLauncherScript -LauncherPath $guardLauncherPath -StartFilePath $StartFile -NoRestartIfRunning
    $guardOutput = @($guardLaunchResult.Lines)
    $guardLog = ''
    foreach ($line in @($guardOutput | ForEach-Object { [string]$_ })) {
        Write-Output $line
        if ($line -match 'guard_log=([^\s]+)') {
            $guardLog = $Matches[1]
        }
    }

    if ([string]::IsNullOrWhiteSpace($guardLog)) {
        $guardLog = Get-AnchorValueFromConfig -Settings $settings -Key 'guard_log'
    }

    $guardRunDirText = if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) { 'unknown' } else { (Convert-ToAnchorPath -Path $currentStageRunDir) }
    Write-Output ("[OPEN-AB-STAGE] monitor_anchor_rebind role=guard run_dir={0}" -f $guardRunDirText)
}

if ($autoStartTakeoverTrigger) {
    if ($monitorStates.ContainsKey('trigger')) {
        $triggerStateObj = $monitorStates.trigger
        Write-Output ("[OPEN-AB-STAGE] monitor_probe role=trigger match_count={0} mismatch_count={1} unbound_count={2} pids={3}" -f
            [int]$triggerStateObj.MatchCount,
            [int]$triggerStateObj.MismatchCount,
            [int]$triggerStateObj.UnboundCount,
            ($triggerStateObj.MatchPids -join ','))
    }

    # Re-probe trigger state at request time to avoid using stale state captured
    # before guard/monitor launch side effects complete.
    $triggerStateLatest = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_takeover_trigger.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
    if ($null -eq $monitorStates) {
        $monitorStates = @{}
    }
    $monitorStates.trigger = $triggerStateLatest

    $restartTrigger = Test-ShouldRestartMonitorRole -Role 'trigger' -ForceRestart $bForceMonitorRestart -SkipRestart $skipMonitorRestart -States $monitorStates
    if ($restartTrigger) {
        $triggerRequestReason = ('stage={0} monitor_chain_bootstrap auto_start_takeover_trigger=true' -f $Stage)
        $pendingTriggerRequest = Get-TriggerRestartRequestFromStartFile -StartFilePath $startFilePath
        $duplicatePendingBootstrapRequest = (
            [bool]$pendingTriggerRequest.Requested -and
            ([string]$pendingTriggerRequest.Source -eq 'open_unattended_ab_stage_window.ps1') -and
            ([string]$pendingTriggerRequest.Reason -eq $triggerRequestReason)
        )

        if ($duplicatePendingBootstrapRequest) {
            Write-Output ("[OPEN-AB-STAGE] trigger_restart_skip reason=duplicate-pending-bootstrap-request stage={0}" -f $Stage)
            Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'trigger_restart_skipped' -Fields @{ stage = $Stage; source = 'stage-window'; reason = 'duplicate-pending-bootstrap-request' }
        }
        else {
            $requestOk = Request-TriggerRestartInStartFile -StartFilePath $startFilePath -Reason $triggerRequestReason -Source 'open_unattended_ab_stage_window.ps1'
            if ($requestOk) {
                Write-Output ("[OPEN-AB-STAGE] trigger_restart_requested_via_guard stage={0}" -f $Stage)
                Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'trigger_restart_requested' -Fields @{ stage = $Stage; source = 'stage-window'; reason = $triggerRequestReason }
            }
            else {
                Write-Output ("[OPEN-AB-STAGE] trigger_restart_request_failed stage={0}" -f $Stage)
            }
        }
    }
    else {
        Write-Output ("[OPEN-AB-STAGE] trigger_restart_skip reason=already-running-for-start-file stage={0}" -f $Stage)
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'trigger_restart_skipped' -Fields @{ stage = $Stage; source = 'stage-window'; reason = 'already-running-for-start-file' }
    }
}
else {
    Write-Output '[OPEN-AB-STAGE] trigger_autostart_skipped enabled=false'
}

$guardStateAtGateBegin = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_session_guard.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
$triggerStateAtGateBegin = if ($autoStartTakeoverTrigger) {
    Get-MonitorBindingState -ScriptLeaf 'unattended_ab_takeover_trigger.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
}
else {
    $null
}

$monitorGateStatus = 'ready'
$monitorGateReason = 'monitor-bootstrap-ready'
try {
    Invoke-MonitorFirstBootstrapBlockingGate -Stage $Stage -StartFilePath $startFilePath -RepoRoot $repoRoot -TimelinePath $monitorTimelinePath -AutoStartTakeoverTrigger $autoStartTakeoverTrigger -GuardLauncherPath $guardLauncherPath -TriggerLauncherPath $triggerLauncherPath -GuardStateAtGateBegin $guardStateAtGateBegin -TriggerStateAtGateBegin $triggerStateAtGateBegin
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($monitorBootstrapGateFile)) {
        if ($settings.Contains('MONITOR_CHAIN_DEGRADED') -and (Convert-ToBooleanSetting -Value ([string]$settings.MONITOR_CHAIN_DEGRADED) -Default $false)) {
            $monitorGateStatus = 'degraded'
            $monitorGateReason = if ($settings.Contains('MONITOR_CHAIN_DEGRADED_REASON')) {
                Convert-ToSingleLineText -Text ([string]$settings.MONITOR_CHAIN_DEGRADED_REASON)
            }
            else {
                'monitor-bootstrap-degraded'
            }
        }

        $gateRelease = [pscustomobject]@{
            schema = 'AB_MONITOR_BOOTSTRAP_GATE_V1'
            status = $monitorGateStatus
            stage = $Stage
            released_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            reason = $monitorGateReason
        }
        [System.IO.File]::WriteAllText($monitorBootstrapGateFile, ($gateRelease | ConvertTo-Json -Depth 4), [System.Text.UTF8Encoding]::new($false))
        Write-Output ("[OPEN-AB-STAGE] monitor_bootstrap_gate release stage={0} status={1} file={2}" -f $Stage, $monitorGateStatus, (Convert-ToAnchorPath -Path $monitorBootstrapGateFile))
    }

    if ($autoStartTakeoverTrigger -and $monitorGateStatus -eq 'ready') {
        $bootstrapRequestReason = ('stage={0} monitor_chain_bootstrap auto_start_takeover_trigger=true' -f $Stage)
        $pendingBootstrapRequest = Get-TriggerRestartRequestFromStartFile -StartFilePath $startFilePath
        $shouldClearBootstrapRequest = (
            [bool]$pendingBootstrapRequest.Requested -and
            ([string]$pendingBootstrapRequest.Source -eq 'open_unattended_ab_stage_window.ps1') -and
            ([string]$pendingBootstrapRequest.Reason -eq $bootstrapRequestReason)
        )

        if ($shouldClearBootstrapRequest) {
            $cleared = Write-TriggerLastActionInStartFile -StartFilePath $startFilePath -Action 'bootstrap-trigger-request-cleared' -ActionBy 'stage-window' -Detail ('stage={0} gate_status=ready' -f $Stage) -ClearRequest $true
            if ($cleared) {
                Write-Output ("[OPEN-AB-STAGE] trigger_restart_request_cleared stage={0} reason=bootstrap-ready" -f $Stage)
            }
            else {
                Write-Output ("[OPEN-AB-STAGE] trigger_restart_request_clear_failed stage={0} reason=bootstrap-ready" -f $Stage)
            }
        }
    }
}

$anchorUpdates = @{}
if (-not [string]::IsNullOrWhiteSpace($currentStageRunDir)) {
    $anchorUpdates.run_dir = Convert-ToAnchorPath -Path $currentStageRunDir
}
if (-not [string]::IsNullOrWhiteSpace($guardLog)) {
    $anchorUpdates.guard_log = Convert-ToAnchorPath -Path $guardLog
    # Derive live_status path from guard_log (same directory, different filename)
    $liveStatusFromGuardLog = $guardLog -replace 'guard\.log$', 'live_status.json'
    if ($liveStatusFromGuardLog -ne $guardLog) {
        $anchorUpdates.live_status = Convert-ToAnchorPath -Path $liveStatusFromGuardLog
    }
}
if ($Stage -eq 'B' -and -not [string]::IsNullOrWhiteSpace($stageRuntimeLogPath)) {
    $anchorUpdates.b_runtime_log = Convert-ToAnchorPath -Path $stageRuntimeLogPath
}

if ($anchorUpdates.Count -gt 0) {
    $updatedNotes = Invoke-SessionAnchorUpdateInStartFile -Path $startFilePath -Anchors $anchorUpdates
    Write-Output ("[OPEN-AB-STAGE] anchor_update notes={0}" -f $updatedNotes)
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'anchor_update' -Fields @{ stage = $Stage; anchors = $anchorUpdates; notes = $updatedNotes }
}

exit 0
