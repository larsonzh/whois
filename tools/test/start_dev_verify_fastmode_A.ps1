param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TaskDefinitionFileName
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$runMutexContext = $null
$mainRunMutexContext = $null
$exitCode = 1
$failureCategory = ''
$failureReason = ''

try {
    $taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName $TaskDefinitionFileName
    Assert-StageWindowInvocation -Stage 'A' -TaskDefinitionRelative $taskDefinitionRelative
    $startFilePath = Resolve-StartFilePathFromEnv
    try {
        $startFileHash = [System.BitConverter]::ToString(
            [System.Security.Cryptography.SHA1]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes(
                    [System.IO.Path]::GetFullPath($startFilePath).ToLowerInvariant()
                )
            )
        ).Replace('-', '').Substring(0, 12).ToLowerInvariant()

        $targetWindowPrefix = 'whois-main-stage-a-'
        $targetWindowTitle = "whois-main-stage-a-$startFileHash"
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
            Write-Output ("[FASTMODE-A] window_title_update=skip reason=foreign-whois-window-protected current_title={0}" -f $currentWindowTitle)
        }
        else {
            $host.UI.RawUI.WindowTitle = $targetWindowTitle
        }
    }
    catch { $null = $_ }

    Invoke-IncrementalEncodingFixGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-A'
    Invoke-SrcCodeEncodingFixGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-A'
    Invoke-StartFieldSyncStrictGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-A' -StartFilePath $startFilePath

    $existingRunPids = @(Get-RunningFastmodeProcessIdList -Role 'A' -RepoRoot $repoRoot -ExcludePid $PID)
    if ($existingRunPids.Count -gt 0) {
        Write-Output ("[FASTMODE-A] restart_precheck existing_count={0} existing_pids={1}" -f $existingRunPids.Count, ($existingRunPids -join ','))
        $stoppedRunPids = @(Invoke-RunningFastmodeProcessStop -ProcessIds $existingRunPids)
        Write-Output ("[FASTMODE-A] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedRunPids.Count, ($stoppedRunPids -join ','))
    }
    else {
        Write-Output "[FASTMODE-A] restart_precheck existing_count=0"
    }

    $mainRunMutexContext = Enter-MainRunMutex -RepoRoot $repoRoot
    Write-Output ("[FASTMODE-A] main_run_mutex={0}" -f [string]$mainRunMutexContext.Name)
    $runMutexContext = Enter-RunMutex -Role 'A' -RepoRoot $repoRoot
    Write-Output ("[FASTMODE-A] run_mutex={0}" -f [string]$runMutexContext.Name)
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
        Assert-RemoteBuildLockReady -RepoRoot $repoRoot -RoleTag 'FASTMODE-A' -RemoteIp $remoteIp -RemoteUser $remoteUser -KeyPath $lockCheckKeyPath -LockScope $remoteBuildLockScope -ConflictAction $remoteBuildLockConflictAction
    }
    else {
        Write-Output ("[FASTMODE-A] remote_lock_check required=false action=skip scope={0}" -f $remoteBuildLockScope)
    }

    Assert-NetworkPrecheckReady -RepoRoot $repoRoot -RoleTag 'FASTMODE-A' -RemoteIp $remoteIp -RemoteUser $remoteUser -KeyPath $keyPath

    $entryScript = Join-Path $PSScriptRoot "start_dev_verify_8round_multiround.ps1"
    if (-not (Test-Path -LiteralPath $entryScript)) {
        throw "Entry script not found: $entryScript"
    }

    Write-Output '[FASTMODE-A] stage_banner stage=A reset_policy=restore-source restart_baseline=repo-baseline stage_window_only=true'
    Write-Output ("[FASTMODE-A] task_definition={0}" -f $taskDefinitionRelative)
    Write-Output ("[FASTMODE-A] fast_gate_range={0}-{1}" -f $fastGateStartRound, $fastGateEndRound)

    $multiroundStartTime = Get-Date
    & $entryScript `
        -Stage A `
        -ResetCodeStepState `
        -CodeStepResetPolicy restore-source `
        -TaskDefinitionFile $taskDefinitionRelative `
        -StartRound $fastGateStartRound -EndRound $fastGateEndRound `
        -ResumeFailedRound $resumeFailedRound `
        -DevVerifyStride 2 `
        -VerifyExecutionProfile d6-only `
        -EnableGuardedFastMode $true `
        -EnableGateOnlySourceDrivenSkip $true `
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
        $multiroundStatus = Get-LatestDevVerifyMultiroundFinalStatus -RepoRoot $repoRoot -After $multiroundStartTime
        if ([bool]$multiroundStatus.Available -and -not [string]::IsNullOrWhiteSpace([string]$multiroundStatus.EffectiveFailureCategory)) {
            $failureCategory = [string]$multiroundStatus.EffectiveFailureCategory
            $failureReason = Convert-ToSingleLineText -Text ("start_dev_verify_8round_multiround exited with code=$exitCode; {0}" -f [string]$multiroundStatus.EffectiveFailureReason)
            Write-Output ("[FASTMODE-A] multiround_failure_inherited category={0} reason={1}" -f $failureCategory, $failureReason)
        }
    }
}
catch {
    $failureReason = Convert-ToSingleLineText -Text $_.Exception.Message
    $failureCategory = Get-FastmodeFailureCategory -Message $failureReason

    $exitCode = 1
    Write-Output ("[FASTMODE-A] gate_fail category={0} reason={1}" -f $failureCategory, $failureReason)
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
        $failureReason = 'fastmode-a failed without explicit reason'
    }

    Write-Output ("[FASTMODE-A] fail_reason category={0} detail={1}" -f $failureCategory, $failureReason)
    Write-Output ("A_FAIL_CATEGORY={0}" -f $failureCategory)
    Write-Output ("A_FAIL_REASON={0}" -f $failureReason)

    $null = Wait-MonitorChainHealthy -Roles @('guard', 'trigger') -RepoRoot $repoRoot -StartFilePath $startFilePath -LogPrefix 'FASTMODE-A-EXIT'
}
else {
    $null = Wait-MonitorChainHealthy -Roles @('guard', 'trigger') -RepoRoot $repoRoot -StartFilePath $startFilePath -LogPrefix 'FASTMODE-A-PASS-EXIT'

    # A stage PASS: write A_FINAL_STATUS and A_SUCCESS_SNAPSHOT to start file
    # so guard can detect PASS and auto-launch B
    $sourceState = 'CLEAN'
    try {
        $eaBackup = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $gitStatus = @(& git -C $repoRoot status --short 2>&1 | ForEach-Object { [string]$_ })
        $ErrorActionPreference = $eaBackup
        $filtered = @($gitStatus | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) -and [string]$_ -notmatch '^\s*(warning:|git(\.exe)?\s*:\s*warning:)' })
        $sourceState = if ($filtered.Count -eq 0) { 'CLEAN' } else { ($filtered -join ' | ') }
    }
    catch {
        $sourceState = 'CLEAN'
    }
    # Derive run dir name from latest multiround output directory
    $runDirName = ''
    $multiroundBase = Join-Path $repoRoot 'out/artifacts/dev_verify_multiround'
    if (Test-Path -LiteralPath $multiroundBase) {
        $latestRunDir = @(Get-ChildItem -LiteralPath $multiroundBase -Directory | Sort-Object Name -Descending | Select-Object -First 1)
        if ($latestRunDir.Count -gt 0) { $runDirName = $latestRunDir[0].Name }
    }
    if ([string]::IsNullOrWhiteSpace($runDirName)) { $runDirName = 'unknown-run' }
    $snapshotFinalRel = "out/artifacts/dev_verify_multiround/$runDirName/final_status.json"
    $snapshotSummaryRel = "out/artifacts/dev_verify_multiround/$runDirName/summary.csv"

    $snapshotUpdates = [ordered]@{
        'A_FINAL_STATUS' = 'PASS'
        'SESSION_FINAL_STATUS' = 'RUNNING'
        'A_LAUNCH_PID' = '0'
        'AB_HANDOVER_STATE' = 'A_TO_B_PENDING'
        'AB_HANDOVER_STARTED_AT' = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        'AB_HANDOVER_STARTED_BY' = 'start_dev_verify_fastmode_A.ps1'
        'A_SUCCESS_SNAPSHOT_FINAL_STATUS' = $snapshotFinalRel
        'A_SUCCESS_SNAPSHOT_SUMMARY' = $snapshotSummaryRel
        'A_SUCCESS_SNAPSHOT_SOURCE_STATE' = $sourceState
    }

    try {
        Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values $snapshotUpdates -CommitMode Move -ReadMaxAttempts 5 -WriteMaxAttempts 5 -RetryDelayMs @(200, 200, 200, 200, 200) -RequireExistingFile $true
        Write-Output ("[FASTMODE-A] start_file_update A_FINAL_STATUS=PASS source_state={0}" -f $sourceState)
        Write-Output ("[FASTMODE-A] snapshot_metadata_written A_SUCCESS_SNAPSHOT_* path_refs_only; actual snapshot content (source dir, patch) will be generated by guard via Save-ASuccessSnapshot")
    }
    catch {
        Write-Output ("[FASTMODE-A] start_file_update_failed detail={0}" -f (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}

$exitResult = if ($exitCode -eq 0) { 'pass' } else { 'fail' }
Write-StageExitReasonArtifact -RepoRoot $repoRoot -Stage 'A' -ScriptTag 'FASTMODE-A' -TaskDefinitionFile $TaskDefinitionFileName -Result $exitResult -ExitCode $exitCode -FailureCategory $failureCategory -FailureReason $failureReason -SourceScriptName (Split-Path -Leaf $PSCommandPath)

Write-Output ("A_EXIT={0}" -f $exitCode)
Exit-FastmodeProcess -Code $exitCode -ScriptName 'start_dev_verify_fastmode_a.ps1' -ScriptTag 'FASTMODE-A'
