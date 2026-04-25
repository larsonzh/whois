param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [ValidateRange(1, 8)][int]$StartRound = 7,
    [ValidateRange(1, 8)][int]$EndRound = 8,
    [switch]$StartMonitors,
    [switch]$SkipMonitorRestart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-NormalizedPathIdentity {
    param(
        [AllowEmptyString()][string]$Path,
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $resolved = if ([System.IO.Path]::IsPathRooted($Path)) {
            [System.IO.Path]::GetFullPath($Path)
        }
        else {
            [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
        }

        return $resolved.ToLowerInvariant()
    }
    catch {
        return ''
    }
}

function Get-StartFilePathFromCommandLine {
    param(
        [AllowEmptyString()][string]$CommandLine,
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return ''
    }

    $match = [regex]::Match($CommandLine, '(?i)(?:^|\s)-StartFile\s+("([^"]+)"|''([^'']+)''|([^\s]+))')
    if (-not $match.Success) {
        return ''
    }

    $rawPath = if ($match.Groups[2].Success) {
        $match.Groups[2].Value
    }
    elseif ($match.Groups[3].Success) {
        $match.Groups[3].Value
    }
    else {
        $match.Groups[4].Value
    }

    return Get-NormalizedPathIdentity -Path $rawPath -RepoRoot $RepoRoot
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

function Set-KeyValueFileValues {
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
        Set-Content -LiteralPath $tempPath -Value @($buffer) -Encoding utf8 -ErrorAction Stop
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        $tempPath = ''
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch {}
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

function Update-SessionAnchorsInStartFile {
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
        if ($trimmed -match '^(run_dir|supervisor_log|companion_log|live_status|guard_log)=') {
            continue
        }

        [void]$segments.Add($trimmed)
    }

    foreach ($anchorKey in @('run_dir', 'supervisor_log', 'companion_log', 'live_status', 'guard_log')) {
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
    Set-KeyValueFileValues -Path $Path -Values @{ SESSION_FINAL_NOTES = $newNotes }
    return $newNotes
}

function Get-LatestTimestampedDirectory {
    param(
        [string]$Root,
        [datetime]$After
    )

    if (-not (Test-Path -LiteralPath $Root)) {
        return $null
    }

    $dirs = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9]{8}-[0-9]{6}$' }

    if ($null -ne $After) {
        $dirs = @($dirs | Where-Object { $_.CreationTime -ge $After.AddSeconds(-2) -or $_.LastWriteTime -ge $After.AddSeconds(-2) })
    }

    $candidates = @($dirs | Sort-Object CreationTime, LastWriteTime -Descending | Select-Object -First 1)
    if ($candidates.Count -lt 1) {
        return $null
    }

    return $candidates[0]
}

function Quote-ArgumentIfNeeded {
    param([string]$Value)

    if ($null -eq $Value) {
        return '""'
    }

    if ($Value -match '[\s"]') {
        return '"' + $Value.Replace('"', '\"') + '"'
    }

    return $Value
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

function Set-EnvFromSetting {
    param(
        [string]$EnvName,
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings) {
        return
    }

    if (-not $Settings.Contains($Key)) {
        return
    }

    $value = [string]$Settings[$Key]
    if ([string]::IsNullOrWhiteSpace($value)) {
        return
    }

    [Environment]::SetEnvironmentVariable($EnvName, $value, 'Process')
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
        Set-KeyValueFileValues -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reasonText
            PRECHECK_FAILURE_REASON = $reasonText
        }
        throw ("[{0}] precheck gate blocked: {1}" -f $ScriptTag, $reasonText)
    }

    Write-Output ("[{0}] precheck_gate status=PASS gate=READY remote_lock={1}" -f $ScriptTag, $remoteLockRaw)
}

function Stop-MonitorProcessesForStartFile {
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
                if ($line -notmatch 'unattended_ab_supervisor\.ps1|unattended_ab_companion\.ps1') {
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
        Stop-Process -Id ([int]$targetPid) -Force -ErrorAction SilentlyContinue
    }

    return @($targetPids)
}

if ($StartRound -gt $EndRound) {
    throw 'StartRound must be less than or equal to EndRound.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath
Assert-PrecheckGateReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-RESUME'

$entryScriptPath = Resolve-RepoPath -Path 'tools/test/start_dev_verify_8round_multiround.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$taskDefinition = [string]$settings.A_TASK_DEFINITION
if ([string]::IsNullOrWhiteSpace($taskDefinition)) {
    throw 'A_TASK_DEFINITION is missing in start file.'
}

$taskStaticPrecheckPolicy = if ($settings.Contains('TASK_STATIC_PRECHECK_POLICY') -and -not [string]::IsNullOrWhiteSpace([string]$settings.TASK_STATIC_PRECHECK_POLICY)) {
    [string]$settings.TASK_STATIC_PRECHECK_POLICY
}
else {
    'enforce'
}

Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_LOCAL_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_LOCAL_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REMOTE_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REMOTE_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV4'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV6'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV4'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV6'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TARGETS' -Settings $settings -Key 'NETWORK_PRECHECK_TARGETS'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TIMEOUT_SEC' -Settings $settings -Key 'NETWORK_PRECHECK_TIMEOUT_SEC'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_ENABLED' -Settings $settings -Key 'ROUND_RUNTIME_GATE_ENABLED'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_START_ROUND' -Settings $settings -Key 'ROUND_RUNTIME_GATE_START_ROUND'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MAX_ATTEMPTS' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MAX_ATTEMPTS'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_RETRY_DELAY_SEC' -Settings $settings -Key 'ROUND_RUNTIME_GATE_RETRY_DELAY_SEC'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_NETWORK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_NETWORK'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT'

$argumentList = @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $entryScriptPath,
    '-CodeStepResetPolicy', [string]$settings.RESET_POLICY_A,
    '-TaskDefinitionFile', $taskDefinition,
    '-StartRound', [string]$StartRound,
    '-EndRound', [string]$EndRound,
    '-DevVerifyStride', [string]$settings.DEV_VERIFY_STRIDE_A,
    '-VerifyExecutionProfile', [string]$settings.VERIFY_EXECUTION_PROFILE,
    '-EnableGuardedFastMode', [string]$settings.ENABLE_GUARDED_FAST_MODE,
    '-EnableGateOnlySourceDrivenSkip', [string]$settings.ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP,
    '-RbPreflight', [string]$settings.RB_PREFLIGHT,
    '-RbPreclassTableGuard', [string]$settings.RB_PRECLASS_TABLE_GUARD,
    '-QuietTerminalOutput', 'true',
    '-TerminalWatchdogMode', [string]$settings.TERMINAL_WATCHDOG_MODE,
    '-TerminalWatchdogIntervalSec', [string]$settings.TERMINAL_WATCHDOG_INTERVAL_SEC,
    '-TerminalWatchdogMinAgeSec', [string]$settings.TERMINAL_WATCHDOG_MIN_AGE_SEC,
    '-QuietRemoteBuildLogs', 'false',
    '-TaskStaticPrecheckPolicy', $taskStaticPrecheckPolicy,
    '-TaskDesignQualityPolicy', [string]$settings.TASK_DESIGN_QUALITY_POLICY,
    '-UnknownNoOpBudget', [string]$settings.UNKNOWN_NOOP_BUDGET,
    '-UnknownNoOpConsecutiveLimit', [string]$settings.UNKNOWN_NOOP_CONSECUTIVE_LIMIT,
    '-KeyPath', [string]$settings.REMOTE_KEYPATH,
    '-RemoteIp', [string]$settings.REMOTE_IP,
    '-User', [string]$settings.REMOTE_USER,
    '-Queries', (Quote-ArgumentIfNeeded -Value ([string]$settings.QUERIES))
)

$disableUnknownNoOpBudgetGate = $false
if ($settings.Contains('DISABLE_UNKNOWN_NOOP_BUDGET_GATE')) {
    $rawDisableUnknownNoOpBudgetGate = [string]$settings.DISABLE_UNKNOWN_NOOP_BUDGET_GATE
    if (-not [string]::IsNullOrWhiteSpace($rawDisableUnknownNoOpBudgetGate)) {
        $disableUnknownNoOpBudgetGate = $rawDisableUnknownNoOpBudgetGate.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
    }
}

if ($disableUnknownNoOpBudgetGate) {
    $argumentList += '-DisableUnknownNoOpBudgetGate'
}

$sessionRoot = Join-Path $repoRoot 'out\artifacts\dev_verify_multiround'
$launchTime = Get-Date
$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $argumentList -PassThru

$runDir = $null
for ($attempt = 0; $attempt -lt 24; $attempt++) {
    $runDir = Get-LatestTimestampedDirectory -Root $sessionRoot -After $launchTime
    if ($null -ne $runDir) {
        break
    }

    Start-Sleep -Seconds 5
}

$runDirPath = if ($null -ne $runDir) { $runDir.FullName } else { '' }
Write-Output ("[OPEN-AB-RESUME] pid={0} launcher_pid={1} start_round={2} end_round={3} run_dir={4} task={5}" -f $processInfo.Id, $PID, $StartRound, $EndRound, $runDirPath, $taskDefinition)

$stageAlive = Test-ProcessAlive -ProcessId ([int]$processInfo.Id)
if (-not $stageAlive) {
    $failureDetail = ("stage=A pid={0} exited_before_running_state" -f $processInfo.Id)
    $failureNotes = "stage_launch_fail $failureDetail"
    $failUpdates = @{
        SESSION_FINAL_STATUS = 'BLOCKED'
        A_FINAL_STATUS = 'BLOCKED'
        A_LAUNCH_PID = '0'
        SESSION_FINAL_NOTES = ''
    }

    if ($settings.Contains('B_FINAL_STATUS') -and [string]$settings.B_FINAL_STATUS -eq 'NOT_RUN') {
        $failUpdates['B_FINAL_STATUS'] = 'BLOCKED'
    }

    if ($settings.Contains('SESSION_FINAL_NOTES') -and -not [string]::IsNullOrWhiteSpace([string]$settings.SESSION_FINAL_NOTES)) {
        $failUpdates['SESSION_FINAL_NOTES'] = ([string]$settings.SESSION_FINAL_NOTES + '; ' + $failureNotes)
    }
    else {
        $failUpdates['SESSION_FINAL_NOTES'] = $failureNotes
    }

    Set-KeyValueFileValues -Path $startFilePath -Values $failUpdates
    Write-Output ("[OPEN-AB-RESUME] stage_launch_blocked {0}" -f $failureDetail)
    return
}

$statusUpdates = @{
    SESSION_FINAL_STATUS = 'RUNNING'
    A_FINAL_STATUS = 'RUNNING'
    A_LAUNCH_PID = [string]$processInfo.Id
}
if ($settings.Contains('B_FINAL_STATUS')) {
    $statusUpdates['B_FINAL_STATUS'] = 'NOT_RUN'
}
if ($settings.Contains('B_LAUNCH_PID')) {
    $statusUpdates['B_LAUNCH_PID'] = '0'
}
Set-KeyValueFileValues -Path $startFilePath -Values $statusUpdates
$settings = Read-KeyValueFile -Path $startFilePath
Write-Output '[OPEN-AB-RESUME] stage_status_update stage=A session_status=RUNNING'

if (-not [string]::IsNullOrWhiteSpace($runDirPath)) {
    $updatedNotes = Update-SessionAnchorsInStartFile -Path $startFilePath -Anchors @{ run_dir = (Convert-ToAnchorPath -Path $runDirPath) }
    Write-Output ("[OPEN-AB-RESUME] anchor_update run_dir={0}" -f (Convert-ToAnchorPath -Path $runDirPath))
}
else {
    Write-Output '[OPEN-AB-RESUME] anchor_update run_dir=unknown'
}

$autoStartMonitors = if ($StartMonitors.IsPresent) {
    $true
}
elseif ($settings.Contains('AUTO_START_MONITORS')) {
    Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_MONITORS) -Default $false
}
else {
    $false
}

if (-not $autoStartMonitors) {
    return
}

$restartMonitors = if ($settings.Contains('RESTART_MONITORS_ON_STAGE_RESTART')) {
    Convert-ToBooleanSetting -Value ([string]$settings.RESTART_MONITORS_ON_STAGE_RESTART) -Default $true
}
else {
    $true
}

if ($SkipMonitorRestart.IsPresent) {
    $restartMonitors = $false
}

if ($restartMonitors) {
    $stoppedPids = @(Stop-MonitorProcessesForStartFile -StartFilePath $startFilePath)
    Write-Output ("[OPEN-AB-RESUME] monitor_restart stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
}

$supervisorLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_SUPERVISOR') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_SUPERVISOR)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_SUPERVISOR
}
else {
    'tools/test/open_unattended_ab_supervisor_window.ps1'
}

$companionLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_COMPANION') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_COMPANION)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_COMPANION
}
else {
    'tools/test/open_unattended_ab_companion_window.ps1'
}

$guardLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_GUARD') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_GUARD)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_GUARD
}
else {
    'tools/test/open_unattended_ab_session_guard_window.ps1'
}

$supervisorLauncherPath = Resolve-RepoPath -Path $supervisorLauncherRelative
$companionLauncherPath = Resolve-RepoPath -Path $companionLauncherRelative
$guardLauncherPath = Resolve-RepoPath -Path $guardLauncherRelative

$supervisorOutput = if ([string]::IsNullOrWhiteSpace($runDirPath)) {
    & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound $StartRound
}
else {
    & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound $StartRound -CurrentARunDir $runDirPath
}
$supervisorLog = ''
$liveStatus = ''
foreach ($line in @($supervisorOutput | ForEach-Object { [string]$_ })) {
    Write-Output $line
    if ($line -match 'supervisor_log=([^\s]+)') {
        $supervisorLog = $Matches[1]
    }
    if ($line -match 'live_status=([^\s]+)') {
        $liveStatus = $Matches[1]
    }
}

$companionOutput = if ([string]::IsNullOrWhiteSpace($supervisorLog)) {
    & $companionLauncherPath -StartFile $StartFile
}
else {
    & $companionLauncherPath -StartFile $StartFile -SupervisorLog $supervisorLog
}

$companionLog = ''
foreach ($line in @($companionOutput | ForEach-Object { [string]$_ })) {
    Write-Output $line
    if ($line -match 'companion_log=([^\s]+)$') {
        $companionLog = $Matches[1]
    }
}

$guardOutput = & $guardLauncherPath -StartFile $StartFile
$guardLog = ''
foreach ($line in @($guardOutput | ForEach-Object { [string]$_ })) {
    Write-Output $line
    if ($line -match 'guard_log=([^\s]+)') {
        $guardLog = $Matches[1]
    }
}

$anchorUpdates = @{}
if (-not [string]::IsNullOrWhiteSpace($runDirPath)) {
    $anchorUpdates.run_dir = Convert-ToAnchorPath -Path $runDirPath
}
if (-not [string]::IsNullOrWhiteSpace($supervisorLog)) {
    $anchorUpdates.supervisor_log = Convert-ToAnchorPath -Path $supervisorLog
}
if (-not [string]::IsNullOrWhiteSpace($companionLog)) {
    $anchorUpdates.companion_log = Convert-ToAnchorPath -Path $companionLog
}
if (-not [string]::IsNullOrWhiteSpace($liveStatus)) {
    $anchorUpdates.live_status = Convert-ToAnchorPath -Path $liveStatus
}
if (-not [string]::IsNullOrWhiteSpace($guardLog)) {
    $anchorUpdates.guard_log = Convert-ToAnchorPath -Path $guardLog
}

if ($anchorUpdates.Count -gt 0) {
    $updatedNotes = Update-SessionAnchorsInStartFile -Path $startFilePath -Anchors $anchorUpdates
    Write-Output ("[OPEN-AB-RESUME] anchor_update notes={0}" -f $updatedNotes)
}
