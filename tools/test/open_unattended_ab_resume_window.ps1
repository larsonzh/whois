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
$script:UnhandledExitTag = 'OPEN-AB-RESUME'

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


function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $repoRoot $Path)).Path
}

function Get-StartFileMutexName {
    param([string]$StartFilePath)

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Local\whois-unattended-startfile-write-$hash"
}

function Read-KeyValueFile {
    param([string]$Path)

    $keyLineMap = @{}
    $map = [ordered]@{}
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            $map[$key] = $Matches[2]
        }
    }

    return $map
}

function Invoke-KeyValueFileValueUpdate {
    param(
        [string]$Path,
        [hashtable]$Values
    )

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -StartFilePath $Path))
    $locked = $false
    $tempPath = ''
    try {
        try {
            $locked = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [System.Threading.AbandonedMutexException] {
            $locked = $true
        }

        if (-not $locked) {
            throw "Failed to acquire start-file write lock within timeout: $Path"
        }

        $lines = @()
        if (Test-Path -LiteralPath $Path) {
            $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
        }

        $seenKeys = @{}
        $lineNo = 0
        foreach ($line in $lines) {
            $lineNo++
            if ($line -match '^([^=]+)=(.*)$') {
                $key = $Matches[1].Trim()
                if ($seenKeys.ContainsKey($key)) {
                    throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, [int]$seenKeys[$key], $lineNo)
                }

                $seenKeys[$key] = $lineNo
            }
        }

        $buffer = New-Object 'System.Collections.Generic.List[string]'
        foreach ($line in $lines) {
            [void]$buffer.Add([string]$line)
        }

        foreach ($key in $Values.Keys) {
            $prefix = "$key="
            $found = $false
            for ($index = 0; $index -lt $buffer.Count; $index++) {
                if ($buffer[$index].StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                    $buffer[$index] = $prefix + [string]$Values[$key]
                    $found = $true
                    break
                }
            }

            if (-not $found) {
                [void]$buffer.Add($prefix + [string]$Values[$key])
            }
        }

        $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
        $normalizedLines = @($buffer | ForEach-Object { [string]$_ })
        $text = [string]::Join("`n", $normalizedLines)
        if ($normalizedLines.Count -gt 0) {
            $text += "`n"
        }
        [System.IO.File]::WriteAllText($tempPath, $text, [System.Text.UTF8Encoding]::new($true))
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        $tempPath = ''
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        $mutex.Dispose()
    }
}

function Test-ProcessAlive {
    param([int]$ProcessId)

    if ($ProcessId -le 0) {
        return $false
    }

    return ($null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue))
}

function Convert-ToAnchorPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $normalized = $Path.Trim().Replace('/', '\\')
    if (-not [System.IO.Path]::IsPathRooted($normalized)) {
        return $normalized
    }

    $fullPath = [System.IO.Path]::GetFullPath($normalized)
    $repoRootFull = [System.IO.Path]::GetFullPath($repoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\')
    }

    return $fullPath
}

function Convert-ToBooleanSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Invoke-DispatchDeliveryToggle {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Settings,
        [string]$ScriptTag
    )

    $defaultTriggerCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/dispatch_takeover_to_chat.ps1 -TicketId "%TICKET_ID%" -TicketEvent "%EVENT%" -StartFile "%START_FILE%" -QueuePath "%QUEUE_PATH%" -BriefPath "%BRIEF_PATH%" -NoOpenEditor -SkipClipboard'
    $policyPlan = Get-ChatDispatchPolicyPlan -Settings $Settings -DefaultTriggerCommand $defaultTriggerCommand
    $updates = if ($null -ne $policyPlan) { [hashtable]$policyPlan.Updates } else { @{} }
    $changes = if ($null -ne $policyPlan) { @($policyPlan.Changes) } else { @() }

    if ($updates.Count -gt 0) {
        Invoke-KeyValueFileValueUpdate -Path $Path -Values $updates
        Write-Host ("[{0}] dispatch_policy_autofix applied={1}" -f $ScriptTag, ($changes -join ','))
        return (Read-KeyValueFile -Path $Path)
    }

    $resolvedPolicy = if ($null -ne $policyPlan) { $policyPlan.ResolvedPolicy } else { $null }
    $policySummary = ''
    if ($null -ne $resolvedPolicy) {
        $policySummary = ('work_mode={0} primary={1} fallback={2} final_stop_gate={3}' -f [string]$resolvedPolicy.work_mode, [string]$resolvedPolicy.delivery_primary, [string]$resolvedPolicy.delivery_fallback, [string]$resolvedPolicy.final_stop_gate)
    }
    Write-Host ("[{0}] dispatch_policy_guard status=PASS {1}" -f $ScriptTag, (Convert-ToSingleLineText -Text $policySummary))
    return $Settings
}

function Clear-MonitorChainShutdownRequest {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Settings,
        [string]$ScriptTag
    )

    $requested = $false
    if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REQUESTED')) {
        $requested = Convert-ToBooleanSetting -Value ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REQUESTED) -Default $false
    }

    $reason = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REASON')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_REASON } else { '' }
    $source = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_SOURCE')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_SOURCE } else { '' }
    $requestedAt = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_AT')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_AT } else { '' }
    $detail = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_DETAIL')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_DETAIL } else { '' }

    if (-not $requested -and [string]::IsNullOrWhiteSpace($reason) -and [string]::IsNullOrWhiteSpace($source) -and [string]::IsNullOrWhiteSpace($requestedAt) -and [string]::IsNullOrWhiteSpace($detail)) {
        Write-Host ("[{0}] monitor_chain_shutdown_reset status=PASS" -f $ScriptTag)
        return $Settings
    }

    Invoke-KeyValueFileValueUpdate -Path $Path -Values @{
        MONITOR_CHAIN_SHUTDOWN_REQUESTED = 'false'
        MONITOR_CHAIN_SHUTDOWN_REASON = ''
        MONITOR_CHAIN_SHUTDOWN_SOURCE = ''
        MONITOR_CHAIN_SHUTDOWN_AT = ''
        MONITOR_CHAIN_SHUTDOWN_DETAIL = ''
    }
    Write-Host ("[{0}] monitor_chain_shutdown_reset applied=true" -f $ScriptTag)
    return (Read-KeyValueFile -Path $Path)
}

function Get-NormalizedFinalStatus {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key) -or -not $Settings.Contains($Key)) {
        return ''
    }

    $raw = [string]$Settings[$Key]
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return ''
    }

    return $raw.Trim().ToUpperInvariant()
}

function Get-ParsedPositiveInt {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 0
    }

    $parsed = 0
    if ([int]::TryParse($Value.Trim(), [ref]$parsed) -and $parsed -gt 0) {
        return $parsed
    }

    return 0
}

function Resolve-RoundFromConfig {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key,
        [int]$DefaultValue
    )

    if ($null -eq $Settings -or -not $Settings.Contains($Key)) {
        return $DefaultValue
    }

    $raw = [string]$Settings[$Key]
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $DefaultValue
    }

    $parsed = 0
    if (-not [int]::TryParse($raw.Trim(), [ref]$parsed) -or $parsed -lt 1 -or $parsed -gt 8) {
        throw ("{0} in start file must be an integer within [1,8], actual value='{1}'" -f $Key, $raw)
    }

    return $parsed
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
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
    Invoke-KeyValueFileValueUpdate -Path $startFilePath -Values $roundOverrideUpdates
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
