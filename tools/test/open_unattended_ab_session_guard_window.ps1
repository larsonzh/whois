param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 10)][int]$MaxBRecoveryAttempts = 2,
    [ValidateRange(1, 180)][int]$RecoveryCooldownMinutes = 10
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

function Get-RunningGuardProcessIds {
    param(
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
                if (-not $line.Contains('unattended_ab_session_guard.ps1')) {
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

function Stop-RunningGuardProcesses {
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
$scriptPath = Join-Path $repoRoot 'tools\test\unattended_ab_session_guard.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$existingPids = @(Get-RunningGuardProcessIds -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
if ($existingPids.Count -gt 0) {
    Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck existing_count={0} existing_pids={1}" -f $existingPids.Count, ($existingPids -join ','))
    $stoppedPids = @(Stop-RunningGuardProcesses -ProcessIds $existingPids)
    Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
}
else {
    Write-Output '[OPEN-AB-SESSION-GUARD] restart_precheck existing_count=0'
}

$launchTime = Get-Date
$argumentList = @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $scriptPath,
    '-StartFile', $StartFile,
    '-PollSec', [string]$PollSec,
    '-MaxBRecoveryAttempts', [string]$MaxBRecoveryAttempts,
    '-RecoveryCooldownMinutes', [string]$RecoveryCooldownMinutes
)

$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $argumentList -PassThru
$guardRoot = Join-Path $repoRoot 'out\artifacts\ab_session_guard'
$guardDir = $null
for ($attempt = 0; $attempt -lt 24; $attempt++) {
    $guardDir = Get-LatestTimestampedDirectory -Root $guardRoot -After $launchTime
    if ($null -ne $guardDir) {
        break
    }

    Start-Sleep -Seconds 5
}

$guardLog = if ($null -ne $guardDir) {
    Join-Path $guardDir.FullName 'guard.log'
}
else {
    ''
}

$guardState = if ($null -ne $guardDir) {
    Join-Path $guardDir.FullName 'guard_state.json'
}
else {
    ''
}

Write-Output ("[OPEN-AB-SESSION-GUARD] pid={0} launcher_pid={1} script={2} start_file={3} poll_sec={4} max_b_recovery_attempts={5} recovery_cooldown_minutes={6} guard_log={7} guard_state={8}" -f $processInfo.Id, $PID, $scriptPath, $StartFile, $PollSec, $MaxBRecoveryAttempts, $RecoveryCooldownMinutes, $guardLog, $guardState)