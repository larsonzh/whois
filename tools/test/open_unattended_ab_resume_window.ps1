<#
        A-only resume launcher.

        $normalizedLines = @($buffer | ForEach-Object { [string]$_ })
        $text = [string]::Join("`n", $normalizedLines)
        if ($normalizedLines.Count -gt 0) {
            $text += "`n"
        }
        [System.IO.File]::WriteAllText($tempPath, $text, [System.Text.UTF8Encoding]::new($true))
        - Resume or rerun Stage A within a bounded round range.
        - Optionally relaunch monitor chain for the same start file.

        Non-goals:
        - This script is not a Stage B restart entry.
        - For any Stage B restart or rerun, use:
            tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartMonitors

        Notes:
        - When StartMonitors is enabled, guard may continue the normal
            A -> snapshot -> B orchestration after A reaches PASS.
        - This script itself only launches Stage A.
#>

param(
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [ValidateRange(0, 8)][int]$StartRound = 0,
    [ValidateRange(0, 8)][int]$EndRound = 0,
    [switch]$StartMonitors,
    [switch]$SkipMonitorRestart,
    [switch]$AllowResumeFromPassFinal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'OPEN-AB-RESUME'
$PSDefaultParameterValues['Invoke-KeyValueFileValueUpdateCore:CommitMode'] = 'Move'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

$dispatchPolicyModulePath = Join-Path $PSScriptRoot 'chat_dispatch_policy_compiler.ps1'
if (-not (Test-Path -LiteralPath $dispatchPolicyModulePath)) {
    throw "Missing script: $dispatchPolicyModulePath"
}
. $dispatchPolicyModulePath

$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath
$settings = Invoke-DispatchDeliveryToggle -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-RESUME'
$configuredStartRound = Resolve-RoundFromConfig -Settings $settings -Key 'START_ROUND' -DefaultValue 1
$configuredEndRound = Resolve-RoundFromConfig -Settings $settings -Key 'END_ROUND' -DefaultValue 8
$effectiveStartRound = if ($StartRound -gt 0) { $StartRound } else { $configuredStartRound }
$effectiveEndRound = if ($EndRound -gt 0) { $EndRound } else { $configuredEndRound }
if ($effectiveStartRound -gt $effectiveEndRound) {
    throw ("Effective StartRound must be less than or equal to EndRound. start={0} end={1}" -f $effectiveStartRound, $effectiveEndRound)
}

Write-Output ("[OPEN-AB-RESUME] stage_scope=A-only start_file={0} start_round={1} end_round={2} start_monitors={3} note=use-open_unattended_ab_stage_window.ps1-stage-B-for-b-restart" -f
    $StartFile,
    $effectiveStartRound,
    $effectiveEndRound,
    [string]$StartMonitors.IsPresent)

$existingALaunchPid = if ($settings.Contains('A_LAUNCH_PID')) {
    Get-ParsedPositiveInt -Value ([string]$settings.A_LAUNCH_PID)
}
else {
    0
}

if ($existingALaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $existingALaunchPid)) {
    $aStatus = if ($settings.Contains('A_FINAL_STATUS')) { [string]$settings.A_FINAL_STATUS } else { '' }
    $sessionStatus = if ($settings.Contains('SESSION_FINAL_STATUS')) { [string]$settings.SESSION_FINAL_STATUS } else { '' }
    Write-Output ("[OPEN-AB-RESUME] existing_stage_running stage=A pid={0} a_status={1} session_status={2} action=skip_launch" -f $existingALaunchPid, $aStatus, $sessionStatus)
    exit 0
}

$existingBLaunchPid = if ($settings.Contains('B_LAUNCH_PID')) {
    Get-ParsedPositiveInt -Value ([string]$settings.B_LAUNCH_PID)
}
else {
    0
}

if ($existingBLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $existingBLaunchPid)) {
    $bStatus = if ($settings.Contains('B_FINAL_STATUS')) { [string]$settings.B_FINAL_STATUS } else { '' }
    $sessionStatus = if ($settings.Contains('SESSION_FINAL_STATUS')) { [string]$settings.SESSION_FINAL_STATUS } else { '' }
    Write-Output ("[OPEN-AB-RESUME] peer_stage_running stage=A peer_stage=B peer_pid={0} b_status={1} session_status={2} action=skip_launch" -f $existingBLaunchPid, $bStatus, $sessionStatus)
    exit 0
}

$sessionFinalStatus = Get-NormalizedFinalStatus -Settings $settings -Key 'SESSION_FINAL_STATUS'
$aFinalStatus = Get-NormalizedFinalStatus -Settings $settings -Key 'A_FINAL_STATUS'
$bFinalStatus = Get-NormalizedFinalStatus -Settings $settings -Key 'B_FINAL_STATUS'
$bResumeSemanticsDetected = ($aFinalStatus -eq 'PASS' -and $bFinalStatus -in @('NOT_RUN', 'RUNNING', 'FAIL', 'BLOCKED'))
$bResumeSemanticsReason = ''
if ($bResumeSemanticsDetected) {
    if ($bFinalStatus -in @('FAIL', 'BLOCKED')) {
        $bResumeSemanticsReason = 'b-needs-recovery'
    }
    elseif ($bFinalStatus -eq 'NOT_RUN') {
        $bResumeSemanticsReason = 'a-pass-b-pending'
    }
    else {
        $bResumeSemanticsReason = 'b-running-attach-required'
    }
}

if ($bResumeSemanticsDetected) {
    throw ("[OPEN-AB-RESUME] a_only_guard blocked: start file indicates B-stage recovery semantics (session_status={0}; a_status={1}; b_status={2}; reason={3}); use open_unattended_ab_stage_window.ps1 -Stage B -StartMonitors, or reset the start file to NOT_RUN baseline before rerunning A." -f $sessionFinalStatus, $aFinalStatus, $bFinalStatus, $bResumeSemanticsReason)
}

$passTerminalDetected = ($sessionFinalStatus -eq 'PASS') -or ($aFinalStatus -eq 'PASS' -and $bFinalStatus -eq 'PASS')
if ($passTerminalDetected -and -not $AllowResumeFromPassFinal.IsPresent) {
    Write-Output ("[OPEN-AB-RESUME] pass_terminal_guard session_status={0} a_status={1} b_status={2} action=skip_launch hint=use-AllowResumeFromPassFinal-to-override" -f $sessionFinalStatus, $aFinalStatus, $bFinalStatus)
    exit 0
}

$roundOverrideUpdates = @{}
if ($StartRound -gt 0) {
    $roundOverrideUpdates['START_ROUND'] = [string]$effectiveStartRound
}
if ($EndRound -gt 0) {
    $roundOverrideUpdates['END_ROUND'] = [string]$effectiveEndRound
}

if ($roundOverrideUpdates.Count -gt 0) {
    Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values $roundOverrideUpdates
    $settings = Read-KeyValueFile -Path $startFilePath
    Write-Output ("[OPEN-AB-RESUME] round_override_applied start_round={0} end_round={1}" -f [string]$settings.START_ROUND, [string]$settings.END_ROUND)
}

$stageLauncherPath = Resolve-RepoPath -Path 'tools/test/open_unattended_ab_stage_window.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$stageArgs = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $stageLauncherPath,
    '-Stage', 'A',
    '-StartFile', $startFilePath
)
if ($StartMonitors.IsPresent) {
    $stageArgs += '-StartMonitors'
}
if ($SkipMonitorRestart.IsPresent) {
    $stageArgs += '-SkipMonitorRestart'
}

Write-Output ("[OPEN-AB-RESUME] delegate_to_stage stage=A start_file={0} start_monitors={1} skip_monitor_restart={2}" -f (Convert-ToAnchorPath -Path $startFilePath), [string]$StartMonitors.IsPresent, [string]$SkipMonitorRestart.IsPresent)

$outputLines = @()
$exitCode = 1
try {
    $outputLines = @((& $powershellPath @stageArgs 2>&1) | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
}
catch {
    $outputLines = @($_.Exception.Message)
    $exitCode = 1
}

foreach ($line in @($outputLines)) {
    if (-not [string]::IsNullOrWhiteSpace($line)) {
        Write-Output $line
    }
}

if ($exitCode -ne 0) {
    throw ("[OPEN-AB-RESUME] stage_delegate_failed stage=A exit={0}" -f $exitCode)
}

Write-Output ("[OPEN-AB-RESUME] stage_delegate status=PASS stage=A exit={0}" -f $exitCode)

exit 0
