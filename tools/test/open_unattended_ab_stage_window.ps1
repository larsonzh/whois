param(
    [ValidateSet('A', 'B')][string]$Stage,
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [switch]$StartMonitors,
    [switch]$SkipMonitorRestart,
    [switch]$EnableBMonitorRestart
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

function Get-LatestTimestampedDirectory {
    param(
        [string]$Root,
        [Nullable[datetime]]$After = $null
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

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath

$entryScriptKey = if ($Stage -eq 'A') { 'ENTRY_SCRIPT_A' } else { 'ENTRY_SCRIPT_B' }
$taskKey = if ($Stage -eq 'A') { 'A_TASK_DEFINITION' } else { 'B_TASK_DEFINITION' }

$entryScriptPath = Resolve-RepoPath -Path ([string]$settings[$entryScriptKey])
$taskLeaf = [System.IO.Path]::GetFileName([string]$settings[$taskKey])

$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$stageLaunchTime = Get-Date
$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $entryScriptPath,
    $taskLeaf
) -PassThru

Write-Output ("[OPEN-AB-STAGE] stage={0} pid={1} launcher_pid={2} entry={3} task={4}" -f $Stage, $processInfo.Id, $PID, $entryScriptPath, $taskLeaf)

$autoStartMonitors = $false
if ($Stage -eq 'A') {
    $autoStartMonitors = if ($StartMonitors.IsPresent) {
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
    $autoStartMonitors = $true
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
    Write-Output ("[OPEN-AB-STAGE] monitor_restart stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
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

$supervisorOutput = @()
if ($Stage -eq 'A') {
    $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1
}
else {
    $sessionOutDirRoot = Join-Path $repoRoot 'out\artifacts\dev_verify_multiround'
    $currentBRunDir = ''
    for ($attempt = 0; $attempt -lt 24; $attempt++) {
        $candidate = Get-LatestTimestampedDirectory -Root $sessionOutDirRoot -After $stageLaunchTime
        if ($null -ne $candidate) {
            $currentBRunDir = $candidate.FullName
            break
        }

        Start-Sleep -Seconds 5
    }

    if ([string]::IsNullOrWhiteSpace($currentBRunDir) -and $settings.Contains('SESSION_FINAL_NOTES')) {
        $sessionNotes = [string]$settings.SESSION_FINAL_NOTES
        if ($sessionNotes -match 'run_dir=([^;]+)') {
            $hintRunDir = $Matches[1].Trim()
            if (-not [string]::IsNullOrWhiteSpace($hintRunDir)) {
                try {
                    $currentBRunDir = Resolve-RepoPath -Path $hintRunDir
                }
                catch {
                    $currentBRunDir = ''
                }
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($currentBRunDir)) {
        Write-Output '[OPEN-AB-STAGE] monitor_attach_b run_dir=unknown source=fallback-auto'
        $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B
    }
    else {
        Write-Output ("[OPEN-AB-STAGE] monitor_attach_b run_dir={0}" -f $currentBRunDir)
        $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B -CurrentBRunDir $currentBRunDir
    }
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

foreach ($line in @($companionOutput | ForEach-Object { [string]$_ })) {
    Write-Output $line
}