param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TaskDefinitionFileName
)

$ErrorActionPreference = "Stop"
$script:RuntimeTranscriptStarted = $false

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

function Resolve-RepoScopedPath {
    param(
        [string]$RepoRoot,
        [AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $normalized = $Path.Trim().Replace('/', '\')
        if ([System.IO.Path]::IsPathRooted($normalized)) {
            return [System.IO.Path]::GetFullPath($normalized)
        }

        return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $normalized))
    }
    catch {
        return ''
    }
}

function Resolve-ASnapshotDirectory {
    param(
        [string]$RepoRoot,
        [System.Collections.IDictionary]$StartSettings
    )

    $snapshotFromEnv = Resolve-RepoScopedPath -RepoRoot $RepoRoot -Path ([string]$env:AUTO_B_A_SNAPSHOT_DIR)
    if (-not [string]::IsNullOrWhiteSpace($snapshotFromEnv) -and (Test-Path -LiteralPath $snapshotFromEnv)) {
        return $snapshotFromEnv
    }

    if ($null -ne $StartSettings -and $StartSettings.Contains('A_SUCCESS_SNAPSHOT_FINAL_STATUS')) {
        $statusPath = Resolve-RepoScopedPath -RepoRoot $RepoRoot -Path ([string]$StartSettings.A_SUCCESS_SNAPSHOT_FINAL_STATUS)
        if (-not [string]::IsNullOrWhiteSpace($statusPath)) {
            $statusDir = Split-Path -Parent $statusPath
            if (-not [string]::IsNullOrWhiteSpace($statusDir)) {
                $candidate = Join-Path $statusDir 'a_success_snapshot'
                if (Test-Path -LiteralPath $candidate) {
                    return $candidate
                }
            }
        }
    }

    if ($null -ne $StartSettings -and $StartSettings.Contains('SESSION_FINAL_NOTES')) {
        $snapshotAnchor = Get-LatestAnchorValueFromNoteText -Notes ([string]$StartSettings.SESSION_FINAL_NOTES) -Key 'a_snapshot_dir'
        if (-not [string]::IsNullOrWhiteSpace($snapshotAnchor)) {
            $candidate = Resolve-RepoScopedPath -RepoRoot $RepoRoot -Path $snapshotAnchor
            if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
                return $candidate
            }
        }
    }

    return ''
}

function Get-BSnapshotRestoreDecision {
    param()

    $enabled = $false
    $reason = 'normal-a-to-b'
    $explicitRaw = [string]$env:AUTO_B_RESTORE_FROM_A_SNAPSHOT
    $previousARaw = [string]$env:AUTO_A_PREVIOUS_FINAL_STATUS
    $previousBRaw = [string]$env:AUTO_B_PREVIOUS_FINAL_STATUS

    if (-not [string]::IsNullOrWhiteSpace($explicitRaw)) {
        $enabled = Convert-ToBooleanSetting -Value $explicitRaw -Default $false
        $reason = "env_auto_b_restore_from_a_snapshot=$explicitRaw"
    }
    elseif ((-not [string]::IsNullOrWhiteSpace($previousARaw)) -or (-not [string]::IsNullOrWhiteSpace($previousBRaw))) {
        $previousA = $previousARaw.Trim().ToUpperInvariant()
        $previousB = $previousBRaw.Trim().ToUpperInvariant()
        if ($previousA -eq 'PASS' -and ($previousB -in @('FAIL', 'BLOCKED'))) {
            $enabled = $true
            $reason = "derived_previous_status a=$previousA b=$previousB"
        }
        else {
            $reason = "derived_previous_status_skip a=$previousA b=$previousB"
        }
    }

    $startFilePath = Resolve-StartFilePathFromEnv
    $startSettings = $null
    if (-not [string]::IsNullOrWhiteSpace($startFilePath) -and (Test-Path -LiteralPath $startFilePath)) {
        $startSettings = Read-KeyValueFile -Path $startFilePath
    }

    if (-not $enabled -and $null -ne $startSettings) {
        $aCurrent = if ($startSettings.Contains('A_FINAL_STATUS')) { ([string]$startSettings.A_FINAL_STATUS).Trim().ToUpperInvariant() } else { '' }
        $bCurrent = if ($startSettings.Contains('B_FINAL_STATUS')) { ([string]$startSettings.B_FINAL_STATUS).Trim().ToUpperInvariant() } else { '' }
        if ($aCurrent -eq 'PASS' -and ($bCurrent -in @('FAIL', 'BLOCKED'))) {
            $enabled = $true
            $reason = "derived_current_status a=$aCurrent b=$bCurrent"
        }
    }

    if ($enabled -and $null -eq $startSettings) {
        if ([string]::IsNullOrWhiteSpace($startFilePath)) {
            throw 'A snapshot restore requested but AUTO_START_FILE_PATH is not set.'
        }

        throw "A snapshot restore requested but start file is unavailable: $startFilePath"
    }

    return [pscustomobject]@{
        Enabled = $enabled
        Reason = $reason
        StartFilePath = $startFilePath
        StartSettings = $startSettings
    }
}

function Restore-AStageSnapshotSource {
    param(
        [string]$RepoRoot,
        [System.Collections.IDictionary]$StartSettings
    )

    if ($null -eq $StartSettings) {
        throw 'A snapshot restore requested but start file settings are not available.'
    }

    $snapshotDir = Resolve-ASnapshotDirectory -RepoRoot $RepoRoot -StartSettings $StartSettings
    if ([string]::IsNullOrWhiteSpace($snapshotDir)) {
        throw 'A snapshot restore requested but a_success_snapshot directory could not be resolved from start file.'
    }

    $sourceDir = Join-Path $snapshotDir 'source'
    if (-not (Test-Path -LiteralPath $sourceDir)) {
        throw "A snapshot restore requested but source directory is missing: $sourceDir"
    }

    try {
        $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    }
    catch {
        throw ("A snapshot restore failed to normalize repo root path: {0}" -f (Convert-ToSingleLineText -Text ([string]$RepoRoot)))
    }

    try {
        $sourceDirFull = [System.IO.Path]::GetFullPath($sourceDir)
    }
    catch {
        throw ("A snapshot restore failed to normalize snapshot source directory: {0}" -f (Convert-ToSingleLineText -Text ([string]$sourceDir)))
    }

    $restoredCount = 0
    $missingCount = 0
    $unsafeCount = 0
    $unsafeDetails = New-Object 'System.Collections.Generic.List[string]'
    $restoreMode = 'tree'

    $sourceFilesPath = Join-Path $snapshotDir 'source_files.txt'
    $listEntries = @()
    if (Test-Path -LiteralPath $sourceFilesPath) {
        $listEntries = @(
            Get-Content -LiteralPath $sourceFilesPath -Encoding utf8 -ErrorAction Stop |
                ForEach-Object { [string]$_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        )
    }

    if ($listEntries.Count -gt 0) {
        $restoreMode = 'list'
        foreach ($relativeRaw in $listEntries) {
                $relativePath = ([string]$relativeRaw).Trim().TrimStart([char]0xFEFF).Replace('/', '\\')
            if ([string]::IsNullOrWhiteSpace($relativePath)) {
                continue
            }

            try {
                $snapshotFilePath = [System.IO.Path]::GetFullPath((Join-Path $sourceDir $relativePath))
            }
            catch {
                $unsafeCount++
                if ($unsafeDetails.Count -lt 3) {
                    [void]$unsafeDetails.Add(("snapshot-path-invalid:{0}" -f (Convert-ToSingleLineText -Text $relativePath)))
                }
                continue
            }
            if (-not $snapshotFilePath.StartsWith($sourceDirFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                $unsafeCount++
                if ($unsafeDetails.Count -lt 3) {
                    [void]$unsafeDetails.Add(("snapshot-path-escaped:{0}" -f (Convert-ToSingleLineText -Text $relativePath)))
                }
                continue
            }
            if (-not (Test-Path -LiteralPath $snapshotFilePath)) {
                $missingCount++
                continue
            }

            try {
                $destinationPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $relativePath))
            }
            catch {
                $unsafeCount++
                if ($unsafeDetails.Count -lt 3) {
                    [void]$unsafeDetails.Add(("destination-path-invalid:{0}" -f (Convert-ToSingleLineText -Text $relativePath)))
                }
                continue
            }
            if (-not $destinationPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                $unsafeCount++
                if ($unsafeDetails.Count -lt 3) {
                    [void]$unsafeDetails.Add(("destination-path-escaped:{0}" -f (Convert-ToSingleLineText -Text $relativePath)))
                }
                continue
            }

            $destinationParent = Split-Path -Parent $destinationPath
            if (-not [string]::IsNullOrWhiteSpace($destinationParent) -and -not (Test-Path -LiteralPath $destinationParent)) {
                New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
            }

            Copy-Item -LiteralPath $snapshotFilePath -Destination $destinationPath -Force
            $restoredCount++
        }
    }
    else {
        $snapshotFiles = @(Get-ChildItem -LiteralPath $sourceDir -File -Recurse -ErrorAction SilentlyContinue)
        foreach ($snapshotFile in $snapshotFiles) {
            $relativePath = $snapshotFile.FullName.Substring($sourceDirFull.Length).TrimStart('\\')
            if ([string]::IsNullOrWhiteSpace($relativePath)) {
                continue
            }

            try {
                $destinationPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $relativePath))
            }
            catch {
                $unsafeCount++
                if ($unsafeDetails.Count -lt 3) {
                    [void]$unsafeDetails.Add(("destination-path-invalid:{0}" -f (Convert-ToSingleLineText -Text $relativePath)))
                }
                continue
            }
            if (-not $destinationPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                $unsafeCount++
                if ($unsafeDetails.Count -lt 3) {
                    [void]$unsafeDetails.Add(("destination-path-escaped:{0}" -f (Convert-ToSingleLineText -Text $relativePath)))
                }
                continue
            }

            $destinationParent = Split-Path -Parent $destinationPath
            if (-not [string]::IsNullOrWhiteSpace($destinationParent) -and -not (Test-Path -LiteralPath $destinationParent)) {
                New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
            }

            Copy-Item -LiteralPath $snapshotFile.FullName -Destination $destinationPath -Force
            $restoredCount++
        }
    }

    return [pscustomobject]@{
        SnapshotDir = $snapshotDir
        RestoreMode = $restoreMode
        RestoredCount = $restoredCount
        MissingCount = $missingCount
        UnsafeCount = $unsafeCount
        UnsafeDetails = @($unsafeDetails)
    }
}

function Resolve-StageRuntimeLogPath {
    param(
        [string]$RepoRoot,
        [string]$StageTag
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$env:AUTO_STAGE_RUNTIME_LOG_PATH)) {
        try {
            return [System.IO.Path]::GetFullPath([string]$env:AUTO_STAGE_RUNTIME_LOG_PATH)
        }
        catch {
            return [string]$env:AUTO_STAGE_RUNTIME_LOG_PATH
        }
    }

    $stageName = $StageTag.Trim().ToUpperInvariant()
    $runtimeRoot = Join-Path $RepoRoot (Join-Path 'out\artifacts\ab_stage_runtime' $stageName)
    if (-not (Test-Path -LiteralPath $runtimeRoot)) {
        New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
    }

    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
    return (Join-Path $runtimeRoot ("{0}_runtime_{1}_pid{2}.log" -f $stageName.ToLowerInvariant(), $stamp, $PID))
}

function Invoke-StageRuntimeTranscriptStart {
    param(
        [string]$RepoRoot,
        [string]$StageTag,
        [string]$ScriptTag
    )

    $runtimeLogPath = ''
    try {
        $runtimeLogPath = Resolve-StageRuntimeLogPath -RepoRoot $RepoRoot -StageTag $StageTag
    }
    catch {
        Write-Output ("[{0}] runtime_log_unavailable detail={1}" -f $ScriptTag, (Convert-ToSingleLineText -Text $_.Exception.Message))
        return ''
    }

    if ([string]::IsNullOrWhiteSpace($runtimeLogPath)) {
        return ''
    }

    $runtimeLogDir = Split-Path -Parent $runtimeLogPath
    if (-not [string]::IsNullOrWhiteSpace($runtimeLogDir) -and -not (Test-Path -LiteralPath $runtimeLogDir)) {
        New-Item -ItemType Directory -Path $runtimeLogDir -Force | Out-Null
    }

    try {
        Start-Transcript -LiteralPath $runtimeLogPath -Force | Out-Null
        $script:RuntimeTranscriptStarted = $true
        Set-Item -Path 'Env:AUTO_STAGE_RUNTIME_LOG_PATH' -Value $runtimeLogPath
        Write-Output ("[{0}] runtime_log={1}" -f $ScriptTag, (Convert-ToRepoRelativePath -Path $runtimeLogPath -RepoRoot $RepoRoot))
        return $runtimeLogPath
    }
    catch {
        $script:RuntimeTranscriptStarted = $false
        Write-Output ("[{0}] runtime_log_unavailable detail={1}" -f $ScriptTag, (Convert-ToSingleLineText -Text $_.Exception.Message))
        return ''
    }
}

function Invoke-StageRuntimeTranscriptStop {
    if (-not $script:RuntimeTranscriptStarted) {
        return
    }

    try {
        Stop-Transcript | Out-Null
    }
    catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    finally {
        $script:RuntimeTranscriptStarted = $false
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot
$runtimeLogPath = Invoke-StageRuntimeTranscriptStart -RepoRoot $repoRoot -StageTag 'B' -ScriptTag 'FASTMODE-B'

$runMutexContext = $null
$mainRunMutexContext = $null
$exitCode = 1
$failureCategory = ''
$failureReason = ''

try {
    $taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName $TaskDefinitionFileName
    Assert-StageWindowInvocation -Stage 'B' -TaskDefinitionRelative $taskDefinitionRelative
    $startFilePath = Resolve-StartFilePathFromEnv
    try {
        $startFileHash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.SHA1]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes(
                    [System.IO.Path]::GetFullPath($startFilePath).ToLowerInvariant()
                )
            )
        ).Replace('-', '').Substring(0, 12).ToLowerInvariant()

        $targetWindowPrefix = 'whois-main-stage-b-'
        $targetWindowTitle = "whois-main-stage-b-$startFileHash"
        $currentWindowTitle = ''
        try {
            $currentWindowTitle = [string]$host.UI.RawUI.WindowTitle
        }
        catch {
            $currentWindowTitle = ''
        }

        $normalizedWindowTitle = if ([string]::IsNullOrWhiteSpace($currentWindowTitle)) {
            ''
        }
        else {
            $currentWindowTitle.Trim().ToLowerInvariant()
        }

        $isWhoisTitle = $normalizedWindowTitle.StartsWith('whois-')
        $isOwnWindow = $normalizedWindowTitle.StartsWith($targetWindowPrefix)
        if ($isWhoisTitle -and -not $isOwnWindow) {
            Write-Output ("[FASTMODE-B] window_title_update=skip reason=foreign-whois-window-protected current_title={0}" -f $currentWindowTitle)
        }
        else {
            $host.UI.RawUI.WindowTitle = $targetWindowTitle
        }
    }
    catch { $null = $_ }

    Invoke-IncrementalEncodingFixGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-B'
    Invoke-SrcCodeEncodingFixGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-B'
    Invoke-StartFieldSyncStrictGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-B' -StartFilePath $startFilePath
    Invoke-StatusTicketMiniRegressionGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-B'

    $existingRunPids = @(Get-RunningFastmodeProcessIdList -Role 'B' -RepoRoot $repoRoot -ExcludePid $PID)
    if ($existingRunPids.Count -gt 0) {
        Write-Output ("[FASTMODE-B] [{0}] restart_precheck existing_count={1} existing_pids={2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $existingRunPids.Count, ($existingRunPids -join ','))
        $stoppedRunPids = @(Invoke-RunningFastmodeProcessStop -ProcessIds $existingRunPids)
        Write-Output ("[FASTMODE-B] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedRunPids.Count, ($stoppedRunPids -join ','))
    }
    else {
        Write-Output ("[FASTMODE-B] [{0}] restart_precheck existing_count=0" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    }

    $mainRunMutexContext = Enter-MainRunMutex -RepoRoot $repoRoot
    Write-Output ("[FASTMODE-B] main_run_mutex={0}" -f [string]$mainRunMutexContext.Name)

    $runMutexContext = Enter-RunMutex -Role 'B' -RepoRoot $repoRoot
    Write-Output ("[FASTMODE-B] run_mutex={0}" -f [string]$runMutexContext.Name)
    $taskDefinitionAbsolute = Join-Path $repoRoot ($taskDefinitionRelative -replace "/", [System.IO.Path]::DirectorySeparatorChar)

    if (-not (Test-Path -LiteralPath $taskDefinitionAbsolute)) {
        throw "Task definition file not found: $taskDefinitionRelative"
    }

    if (Select-String -Path $taskDefinitionAbsolute -Pattern "TODO_" -Quiet) {
        throw "Task definition still contains TODO placeholders: $taskDefinitionRelative"
    }

    $remoteIp = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_IP)) { "10.0.0.199" } else { $env:AUTO_REMOTE_IP }
    $remoteUser = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_USER)) { "larson" } else { $env:AUTO_REMOTE_USER }
    $keyPath = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_KEYPATH)) { "/c/Users/$env:USERNAME/.ssh/id_rsa" } else { $env:AUTO_REMOTE_KEYPATH }
    $queries = if ([string]::IsNullOrWhiteSpace($env:AUTO_QUERIES)) { "8.8.8.8 1.1.1.1 10.0.0.8" } else { $env:AUTO_QUERIES }
    $terminalWatchdogMode = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_MODE)) { "safe" } else { $env:AUTO_TERMINAL_WATCHDOG_MODE }
    $terminalWatchdogIntervalSec = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC)) { 120 } else { [int]$env:AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC }
    $terminalWatchdogMinAgeSec = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC)) { 600 } else { [int]$env:AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC }
    $taskStaticPrecheckPolicy = if ([string]::IsNullOrWhiteSpace($env:AUTO_TASK_STATIC_PRECHECK_POLICY)) { "enforce" } else { [string]$env:AUTO_TASK_STATIC_PRECHECK_POLICY }
    $taskStaticPrecheckFailOnWarnings = Convert-ToBooleanSetting -Value ([string]$env:AUTO_TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS) -Default $true
    $fastGateStartRound = if ([string]::IsNullOrWhiteSpace($env:AUTO_FASTMODE_GATE_START_ROUND)) { 1 } else { [int]$env:AUTO_FASTMODE_GATE_START_ROUND }
    $fastGateEndRound = if ([string]::IsNullOrWhiteSpace($env:AUTO_FASTMODE_GATE_END_ROUND)) { 2 } else { [int]$env:AUTO_FASTMODE_GATE_END_ROUND }
    $resumeFailedRound = if ([string]::IsNullOrWhiteSpace($env:AUTO_RESUME_FAILED_ROUND)) { '' } else { [string]$env:AUTO_RESUME_FAILED_ROUND }
    $roundTaskStaticGateEnabled = Convert-ToBooleanSetting -Value ([string]$env:AUTO_ROUND_TASK_STATIC_GATE_ENABLED) -Default $true
    $roundTaskStaticGateStartRound = if ([string]::IsNullOrWhiteSpace($env:AUTO_ROUND_TASK_STATIC_GATE_START_ROUND)) { $fastGateStartRound } else { [int]$env:AUTO_ROUND_TASK_STATIC_GATE_START_ROUND }
    $roundTaskStaticGateEndRound = if ([string]::IsNullOrWhiteSpace($env:AUTO_ROUND_TASK_STATIC_GATE_END_ROUND)) { $fastGateEndRound } else { [int]$env:AUTO_ROUND_TASK_STATIC_GATE_END_ROUND }
    $roundTaskStaticGateOperationIndex = if ([string]::IsNullOrWhiteSpace($env:AUTO_ROUND_TASK_STATIC_GATE_OPERATION_INDEX)) { 0 } else { [int]$env:AUTO_ROUND_TASK_STATIC_GATE_OPERATION_INDEX }

    $taskStaticPrecheckPolicy = $taskStaticPrecheckPolicy.Trim().ToLowerInvariant()
    if ($taskStaticPrecheckPolicy -notin @('off', 'warn', 'enforce')) {
        throw "Invalid AUTO_TASK_STATIC_PRECHECK_POLICY value: $taskStaticPrecheckPolicy"
    }
    if ($fastGateStartRound -lt 1 -or $fastGateStartRound -gt 8 -or $fastGateEndRound -lt 1 -or $fastGateEndRound -gt 8 -or $fastGateStartRound -gt $fastGateEndRound) {
        throw "Invalid AUTO_FASTMODE_GATE_START_ROUND/AUTO_FASTMODE_GATE_END_ROUND values: $fastGateStartRound/$fastGateEndRound"
    }
    if ($roundTaskStaticGateStartRound -lt 1 -or $roundTaskStaticGateStartRound -gt 8 -or $roundTaskStaticGateEndRound -lt 1 -or $roundTaskStaticGateEndRound -gt 8 -or $roundTaskStaticGateStartRound -gt $roundTaskStaticGateEndRound) {
        throw "Invalid AUTO_ROUND_TASK_STATIC_GATE_START_ROUND/AUTO_ROUND_TASK_STATIC_GATE_END_ROUND values: $roundTaskStaticGateStartRound/$roundTaskStaticGateEndRound"
    }
    if ($roundTaskStaticGateOperationIndex -lt 0 -or $roundTaskStaticGateOperationIndex -gt 256) {
        throw "Invalid AUTO_ROUND_TASK_STATIC_GATE_OPERATION_INDEX value: $roundTaskStaticGateOperationIndex"
    }

    $remoteBuildLockRequired = Convert-ToBooleanSetting -Value ([string]$env:AUTO_REMOTE_BUILD_LOCK_REQUIRED) -Default $true
    $remoteBuildLockScope = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_BUILD_LOCK_SCOPE)) { 'remote-base' } else { [string]$env:AUTO_REMOTE_BUILD_LOCK_SCOPE }
    $remoteBuildLockConflictAction = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_BUILD_LOCK_CONFLICT_ACTION)) { 'stop-before-build' } else { [string]$env:AUTO_REMOTE_BUILD_LOCK_CONFLICT_ACTION }

    if ($remoteBuildLockRequired) {
        $lockCheckKeyPath = Resolve-RemoteKeyPath -KeyPath $keyPath -UseDefaultSshKeyFallback -Purpose 'SSH private key for remote lock check'
        Assert-RemoteBuildLockReady -RepoRoot $repoRoot -RoleTag 'FASTMODE-B' -RemoteIp $remoteIp -RemoteUser $remoteUser -KeyPath $lockCheckKeyPath -LockScope $remoteBuildLockScope -ConflictAction $remoteBuildLockConflictAction -IncludeRuntimeLogPath
    }
    else {
        Write-Output ("[FASTMODE-B] remote_lock_check required=false action=skip scope={0}" -f $remoteBuildLockScope)
    }

    Assert-NetworkPrecheckReady -RepoRoot $repoRoot -RoleTag 'FASTMODE-B' -RemoteIp $remoteIp -RemoteUser $remoteUser -KeyPath $keyPath

    $snapshotRestoreDecision = Get-BSnapshotRestoreDecision
    Write-Output ("[FASTMODE-B] stage_banner stage=B reset_policy=state-only restart_baseline=a-success-snapshot restore_from_a_snapshot={0} stage_window_only=true" -f [string]$snapshotRestoreDecision.Enabled)
    if ([bool]$snapshotRestoreDecision.Enabled) {
        Write-Output ("[FASTMODE-B] restore_from_a_snapshot enabled=true reason={0}" -f [string]$snapshotRestoreDecision.Reason)
        $snapshotRestoreResult = Restore-AStageSnapshotSource -RepoRoot $repoRoot -StartSettings $snapshotRestoreDecision.StartSettings
        Write-Output ("[FASTMODE-B] restore_from_a_snapshot snapshot_dir={0} mode={1} restored_files={2} missing_files={3} unsafe_entries={4}" -f (Convert-ToRepoRelativePath -Path ([string]$snapshotRestoreResult.SnapshotDir) -RepoRoot $repoRoot), [string]$snapshotRestoreResult.RestoreMode, [int]$snapshotRestoreResult.RestoredCount, [int]$snapshotRestoreResult.MissingCount, [int]$snapshotRestoreResult.UnsafeCount)
        if ([int]$snapshotRestoreResult.UnsafeCount -gt 0 -and $snapshotRestoreResult.PSObject.Properties.Name -contains 'UnsafeDetails') {
            Write-Output ("[FASTMODE-B] restore_from_a_snapshot unsafe_detail={0}" -f (Convert-ToSingleLineText -Text (($snapshotRestoreResult.UnsafeDetails -join ' | '))))
        }

        Write-Output '[FASTMODE-B] restore_from_a_snapshot post_restore_encoding_fix=begin'
        Invoke-IncrementalEncodingFixGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-B'
        Invoke-SrcCodeEncodingFixGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-B'
        Write-Output '[FASTMODE-B] restore_from_a_snapshot post_restore_encoding_fix=end'
    }
    else {
        Write-Output ("[FASTMODE-B] restore_skip reason={0}" -f [string]$snapshotRestoreDecision.Reason)
    }

    $entryScript = Join-Path $PSScriptRoot "start_dev_verify_8round_multiround.ps1"
    if (-not (Test-Path -LiteralPath $entryScript)) {
        throw "Entry script not found: $entryScript"
    }

    Write-Output ("[FASTMODE-B] task_definition={0}" -f $taskDefinitionRelative)
    Write-Output ("[FASTMODE-B] fast_gate_range={0}-{1}" -f $fastGateStartRound, $fastGateEndRound)

    & $entryScript `
        -Stage B `
        -ResetCodeStepState `
        -CodeStepResetPolicy state-only `
        -TaskDefinitionFile $taskDefinitionRelative `
        -StartRound $fastGateStartRound -EndRound $fastGateEndRound `
        -DevVerifyStride 2 `
        -VerifyExecutionProfile d6-only `
        -EnableGuardedFastMode $true `
        -EnableGateOnlySourceDrivenSkip $true `
        -ResumeFailedRound $resumeFailedRound `
        -RbPreflight 1 -RbPreclassTableGuard 1 `
        -QuietTerminalOutput true `
        -TerminalWatchdogMode $terminalWatchdogMode `
        -TerminalWatchdogIntervalSec $terminalWatchdogIntervalSec `
        -TerminalWatchdogMinAgeSec $terminalWatchdogMinAgeSec `
        -QuietRemoteBuildLogs false `
        -TaskStaticPrecheckPolicy $taskStaticPrecheckPolicy `
        -TaskStaticPrecheckFailOnWarnings $taskStaticPrecheckFailOnWarnings `
        -EnableRoundTaskStaticGate $roundTaskStaticGateEnabled `
        -RoundTaskStaticGateStartRound $roundTaskStaticGateStartRound `
        -RoundTaskStaticGateEndRound $roundTaskStaticGateEndRound `
        -RoundTaskStaticGateOperationIndex $roundTaskStaticGateOperationIndex `
        -TaskDesignQualityPolicy enforce `
        -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 `
        -DisableUnknownNoOpBudgetGate:$false `
        -KeyPath $keyPath -RemoteIp $remoteIp -User $remoteUser -Queries $queries

    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    if ($exitCode -ne 0) {
        $failureCategory = 'runner-fail'
        $failureReason = "start_dev_verify_8round_multiround exited with code=$exitCode"
    }
}
catch {
    $failureReason = Convert-ToSingleLineText -Text $_.Exception.Message
    $failureCategory = Get-FastmodeFailureCategory -Message $failureReason -IncludeSnapshotRestore
    $exitCode = 1
    Write-Output ("[FASTMODE-B] gate_fail category={0} reason={1}" -f $failureCategory, $failureReason)
}
finally {
    if ($null -ne $runMutexContext -and $null -ne $runMutexContext.Mutex) {
        try {
            $runMutexContext.Mutex.ReleaseMutex() | Out-Null
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        finally {
            $runMutexContext.Mutex.Dispose()
        }
    }

    if ($null -ne $mainRunMutexContext -and $null -ne $mainRunMutexContext.Mutex) {
        try {
            $mainRunMutexContext.Mutex.ReleaseMutex() | Out-Null
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        finally {
            $mainRunMutexContext.Mutex.Dispose()
        }
    }
}

if ($exitCode -ne 0) {
    if ([string]::IsNullOrWhiteSpace($failureCategory)) {
        $failureCategory = 'runtime-fail'
    }
    if ([string]::IsNullOrWhiteSpace($failureReason)) {
        $failureReason = 'fastmode-b failed without explicit reason'
    }

    Write-Output ("[FASTMODE-B] fail_reason category={0} detail={1}" -f $failureCategory, $failureReason)
    Write-Output ("B_FAIL_CATEGORY={0}" -f $failureCategory)
    Write-Output ("B_FAIL_REASON={0}" -f $failureReason)

    Invoke-MonitorChainHealthCheck -Roles @('guard', 'trigger') -RepoRoot $repoRoot -StartFilePath $startFilePath -LogPrefix 'FASTMODE-B'
}
else {
    Invoke-MonitorChainHealthCheck -Roles @('guard', 'trigger') -RepoRoot $repoRoot -StartFilePath $startFilePath -LogPrefix 'FASTMODE-B-PASS'
}

$exitResult = if ($exitCode -eq 0) { 'pass' } else { 'fail' }
Write-StageExitReasonArtifact -RepoRoot $repoRoot -Stage 'B' -ScriptTag 'FASTMODE-B' -TaskDefinitionFile $TaskDefinitionFileName -Result $exitResult -ExitCode $exitCode -FailureCategory $failureCategory -FailureReason $failureReason -SourceScriptName (Split-Path -Leaf $PSCommandPath) -IncludeRuntimeLogPath

Write-Output ("B_EXIT={0}" -f $exitCode)
Exit-FastmodeProcess -Code $exitCode -ScriptName 'start_dev_verify_fastmode_b.ps1' -ScriptTag 'FASTMODE-B' -StopRuntimeTranscript
