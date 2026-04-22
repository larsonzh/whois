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

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $Path)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

function Set-KeyValueFileValues {
    param(
        [string]$Path,
        [hashtable]$Values
    )

    $lines = @()
    if (Test-Path -LiteralPath $Path) {
        $lines = @(Get-Content -LiteralPath $Path)
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

    Set-Content -LiteralPath $Path -Value @($buffer) -Encoding utf8
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
        if ($trimmed -match '^(run_dir|supervisor_log|companion_log)=') {
            continue
        }

        [void]$segments.Add($trimmed)
    }

    foreach ($anchorKey in @('run_dir', 'supervisor_log', 'companion_log')) {
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

function Stop-MonitorProcessesForStartFile {
    param([string]$StartFilePath)

    $startFileLeaf = [System.IO.Path]::GetFileName($StartFilePath).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($startFileLeaf)) {
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
                ($line -match 'unattended_ab_supervisor\.ps1|unattended_ab_companion\.ps1') -and $line.Contains($startFileLeaf)
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
$settings = Read-KeyValueFile -Path (Resolve-RepoPath -Path $StartFile)

$entryScriptPath = Resolve-RepoPath -Path 'tools/test/start_dev_verify_8round_multiround.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$taskDefinition = [string]$settings.A_TASK_DEFINITION
if ([string]::IsNullOrWhiteSpace($taskDefinition)) {
    throw 'A_TASK_DEFINITION is missing in start file.'
}

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

$startFilePath = Resolve-RepoPath -Path $StartFile
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

$supervisorLauncherPath = Resolve-RepoPath -Path $supervisorLauncherRelative
$companionLauncherPath = Resolve-RepoPath -Path $companionLauncherRelative

$supervisorOutput = if ([string]::IsNullOrWhiteSpace($runDirPath)) {
    & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound $StartRound
}
else {
    & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound $StartRound -CurrentARunDir $runDirPath
}
$supervisorLog = ''
foreach ($line in @($supervisorOutput | ForEach-Object { [string]$_ })) {
    Write-Output $line
    if ($line -match 'supervisor_log=([^\s]+)$') {
        $supervisorLog = $Matches[1]
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

if ($anchorUpdates.Count -gt 0) {
    $updatedNotes = Update-SessionAnchorsInStartFile -Path $startFilePath -Anchors $anchorUpdates
    Write-Output ("[OPEN-AB-RESUME] anchor_update notes={0}" -f $updatedNotes)
}
