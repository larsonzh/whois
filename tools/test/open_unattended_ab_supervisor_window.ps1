param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [AllowEmptyString()][string]$CurrentARunDir = '',
    [AllowEmptyString()][string]$CurrentBRunDir = '',
    [ValidateSet('A', 'B')][string]$StartFromStage = 'A',
    [ValidateRange(1, 8)][int]$CurrentAStartRound = 1,
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 3)][int]$MaxStageRestarts = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-RunningMonitorProcessIds {
    param(
        [string]$ScriptLeaf,
        [string]$StartFileIdentity,
        [string]$RepoRoot
    )

    $ids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if (-not $line.Contains($ScriptLeaf)) {
                    return $false
                }

                if ([string]::IsNullOrWhiteSpace($StartFileIdentity)) {
                    return $true
                }

                $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine $commandLine -RepoRoot $RepoRoot
                if ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
                    return $false
                }

                return ($processStartFileIdentity -eq $StartFileIdentity)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    return @($ids)
}

function Stop-RunningMonitorProcesses {
    param([int[]]$ProcessIds)

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($targetPid in @($ProcessIds | Sort-Object -Unique)) {
        if ($targetPid -le 0) {
            continue
        }

        try {
            Stop-Process -Id $targetPid -Force -ErrorAction Stop
            Wait-Process -Id $targetPid -Timeout 20 -ErrorAction SilentlyContinue
            [void]$stopped.Add([int]$targetPid)
        }
        catch {
        }
    }

    return @($stopped)
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

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    (Resolve-Path -LiteralPath $StartFile).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $repoRoot $StartFile)).Path
}
$startFileIdentity = Get-NormalizedPathIdentity -Path $startFilePath -RepoRoot $repoRoot
$scriptPath = Join-Path $repoRoot 'tools\test\unattended_ab_supervisor.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$existingPids = @(Get-RunningMonitorProcessIds -ScriptLeaf 'unattended_ab_supervisor.ps1' -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
if ($existingPids.Count -gt 0) {
    Write-Output ("[OPEN-AB-SUPERVISOR] restart_precheck existing_count={0} existing_pids={1}" -f $existingPids.Count, ($existingPids -join ','))
    $stoppedPids = @(Stop-RunningMonitorProcesses -ProcessIds $existingPids)
    Write-Output ("[OPEN-AB-SUPERVISOR] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
}
else {
    Write-Output '[OPEN-AB-SUPERVISOR] restart_precheck existing_count=0'
}

$launchTime = Get-Date

$argumentList = @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $scriptPath,
    '-StartFile', $StartFile,
    '-StartFromStage', [string]$StartFromStage,
    '-CurrentAStartRound', [string]$CurrentAStartRound,
    '-PollSec', [string]$PollSec,
    '-MaxStageRestarts', [string]$MaxStageRestarts
)

if (-not [string]::IsNullOrWhiteSpace($CurrentARunDir)) {
    $argumentList += @('-CurrentARunDir', $CurrentARunDir)
}

if (-not [string]::IsNullOrWhiteSpace($CurrentBRunDir)) {
    $argumentList += @('-CurrentBRunDir', $CurrentBRunDir)
}

$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $argumentList -PassThru
$supervisorRoot = Join-Path $repoRoot 'out\artifacts\ab_supervisor'
$supervisorDir = $null
for ($attempt = 0; $attempt -lt 24; $attempt++) {
    $supervisorDir = Get-LatestTimestampedDirectory -Root $supervisorRoot -After $launchTime
    if ($null -ne $supervisorDir) {
        break
    }

    Start-Sleep -Seconds 5
}

$supervisorLog = if ($null -ne $supervisorDir) {
    Join-Path $supervisorDir.FullName 'supervisor.log'
}
else {
    ''
}

$liveStatus = if ($null -ne $supervisorDir) {
    Join-Path $supervisorDir.FullName 'live_status.json'
}
else {
    ''
}

Write-Output ("[OPEN-AB-SUPERVISOR] pid={0} launcher_pid={1} script={2} start_file={3} start_from_stage={4} supervisor_log={5} live_status={6}" -f $processInfo.Id, $PID, $scriptPath, $StartFile, $StartFromStage, $supervisorLog, $liveStatus)
