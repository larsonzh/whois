param(
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 10)][int]$MaxBRecoveryAttempts = 2,
    [ValidateRange(1, 180)][int]$RecoveryCooldownMinutes = 10,
    [switch]$NoRestartIfRunning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'OPEN-AB-SESSION-GUARD'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
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

function Get-StartFileLaunchMutexName {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

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
    return "Local\whois-monitor-launch-{0}-{1}" -f $Role, $hash
}

function Enter-LaunchMutex {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

    $name = Get-StartFileLaunchMutexName -Role $Role -StartFilePath $StartFilePath
    $mutex = New-Object System.Threading.Mutex($false, $name)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }

        if (-not $acquired) {
            $mutex.Dispose()
            throw "Timed out waiting for monitor launch mutex: $name"
        }
    }
    catch {
        if ($null -ne $mutex) {
            try { $mutex.Dispose() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        throw
    }

    return [pscustomobject]@{
        Name = $name
        Mutex = $mutex
        Acquired = $acquired
    }
}

function Exit-LaunchMutex {
    param($Context)

    if ($null -eq $Context -or $null -eq $Context.Mutex) {
        return
    }

    if ([bool]$Context.Acquired) {
        try { $Context.Mutex.ReleaseMutex() | Out-Null } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    }

    try { $Context.Mutex.Dispose() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
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

function Get-RunningGuardProcessIdList {
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

function Invoke-RunningGuardProcessStop {
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
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    }

    return @($stopped)
}

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

function Get-LatestAnchorValueFromNoteLog {
    param(
        [AllowEmptyString()][string]$Notes,
        [string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Notes) -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    $parts = @($Notes -split ';')
    for ($index = $parts.Count - 1; $index -ge 0; $index--) {
        $segment = [string]$parts[$index]
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        if ($segment -match ('^\s*' + [regex]::Escape($Key) + '=(.+)$')) {
            return $Matches[1].Trim()
        }
    }

    return ''
}

function Get-AnchorValueFromConfig {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    if (-not $Settings.Contains('SESSION_FINAL_NOTES')) {
        return ''
    }

    return Get-LatestAnchorValueFromNoteLog -Notes ([string]$Settings.SESSION_FINAL_NOTES) -Key $Key
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

    # $After is a value type (datetime) — callers may pass [datetime]::MinValue
    # which would make AddSeconds(-2) underflow. Only apply the cutoff
    # when $After is a meaningful timestamp greater than MinValue.
    if ($After -ne [datetime]::MinValue) {
        try {
            $cutoff = $After.AddSeconds(-2)
        }
        catch {
            # If AddSeconds fails for any reason, fall back to using $After itself
            $cutoff = $After
        }

        $dirs = @($dirs | Where-Object { $_.CreationTime -ge $cutoff -or $_.LastWriteTime -ge $cutoff })
    }

    $candidates = @($dirs | Sort-Object CreationTime, LastWriteTime -Descending | Select-Object -First 1)
    if ($candidates.Count -lt 1) {
        return $null
    }

    return $candidates[0]
}

function Test-ExistingMonitorProcessAlive {
    param(
        [int[]]$ProcessIds,
        [string[]]$EvidencePaths,
        [int]$MaxStaleMinutes = 15
    )

    $thresholdMinutes = if ($MaxStaleMinutes -gt 0) { $MaxStaleMinutes } else { 15 }
    $alivePidCount = 0
    foreach ($candidatePid in @($ProcessIds | Sort-Object -Unique)) {
        if ($candidatePid -le 0) {
            continue
        }

        if ($null -ne (Get-Process -Id $candidatePid -ErrorAction SilentlyContinue)) {
            $alivePidCount++
        }
    }

    if ($alivePidCount -le 0) {
        return $false
    }

    $now = Get-Date
    foreach ($path in @($EvidencePaths)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
            continue
        }

        $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            continue
        }

        $ageMinutes = (New-TimeSpan -Start $item.LastWriteTime -End $now).TotalMinutes
        if ($ageMinutes -le $thresholdMinutes) {
            return $true
        }
    }

    return $false
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    (Resolve-Path -LiteralPath $StartFile).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $repoRoot $StartFile)).Path
}
$settings = Read-KeyValueFile -Path $startFilePath
$startFileIdentity = Get-NormalizedPathIdentity -Path $startFilePath -RepoRoot $repoRoot
$monitorReuseStaleMinutes = 15
if ($settings.Contains('LOCAL_GUARD_MONITOR_REUSE_STALE_MINUTES')) {
    $parsedStale = 0
    if ([int]::TryParse(([string]$settings.LOCAL_GUARD_MONITOR_REUSE_STALE_MINUTES), [ref]$parsedStale)) {
        if ($parsedStale -ge 1 -and $parsedStale -le 120) {
            $monitorReuseStaleMinutes = $parsedStale
        }
    }
}
elseif ($settings.Contains('MONITOR_REUSE_MAX_STALE_MINUTES')) {
    $parsedStale = 0
    if ([int]::TryParse(([string]$settings.MONITOR_REUSE_MAX_STALE_MINUTES), [ref]$parsedStale)) {
        if ($parsedStale -ge 1 -and $parsedStale -le 120) {
            $monitorReuseStaleMinutes = $parsedStale
        }
    }
}
$scriptPath = Join-Path $repoRoot 'tools\test\unattended_ab_session_guard.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$launchMutexContext = Enter-LaunchMutex -Role 'session-guard' -StartFilePath $startFilePath
try {
    $existingPids = @(Get-RunningGuardProcessIdList -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
    $reuseExisting = $false
    $processId = 0

    if ($existingPids.Count -gt 0) {
        if ($NoRestartIfRunning.IsPresent) {
            $probeRoot = Join-Path $repoRoot 'out\artifacts\ab_session_guard'
            $probeDir = Get-LatestTimestampedDirectory -Root $probeRoot -After ([datetime]::MinValue)
            $probePaths = @()
            if ($null -ne $probeDir) {
                $probePaths += Join-Path $probeDir.FullName 'guard.log'
                $probePaths += Join-Path $probeDir.FullName 'guard_state.json'
            }

            $reuseAlive = Test-ExistingMonitorProcessAlive -ProcessIds $existingPids -EvidencePaths $probePaths -MaxStaleMinutes $monitorReuseStaleMinutes
            if ($reuseAlive) {
                Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck existing_count={0} existing_pids={1} mode=reuse stale_min={2}" -f $existingPids.Count, ($existingPids -join ','), $monitorReuseStaleMinutes)
                $reuseExisting = $true
                $processId = [int]$existingPids[0]
            }
            else {
                Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck existing_count={0} existing_pids={1} mode=restart-stale stale_min={2}" -f $existingPids.Count, ($existingPids -join ','), $monitorReuseStaleMinutes)
                $stoppedPids = @(Invoke-RunningGuardProcessStop -ProcessIds $existingPids)
                Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
            }
        }
        else {
            Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck existing_count={0} existing_pids={1}" -f $existingPids.Count, ($existingPids -join ','))
            $stoppedPids = @(Invoke-RunningGuardProcessStop -ProcessIds $existingPids)
            Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
        }
    }

    if (-not $reuseExisting) {
        if ($existingPids.Count -eq 0) {
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
        $processId = [int]$processInfo.Id
    }

    $guardLog = ''
    $guardState = ''
    if ($reuseExisting) {
        $guardLog = Get-AnchorValueFromConfig -Settings $settings -Key 'guard_log'
        if (-not [string]::IsNullOrWhiteSpace($guardLog)) {
            $guardState = Join-Path (Split-Path -Parent $guardLog) 'guard_state.json'
        }
    }

    if ([string]::IsNullOrWhiteSpace($guardLog) -or [string]::IsNullOrWhiteSpace($guardState)) {
        $guardRoot = Join-Path $repoRoot 'out\artifacts\ab_session_guard'
        $guardDir = $null
        for ($attempt = 0; $attempt -lt 24; $attempt++) {
            if ($reuseExisting) {
                $guardDir = Get-LatestTimestampedDirectory -Root $guardRoot -After ([datetime]::MinValue)
            }
            else {
                $guardDir = Get-LatestTimestampedDirectory -Root $guardRoot -After $launchTime
            }
            if ($null -ne $guardDir) {
                break
            }

            Start-Sleep -Seconds 5
        }

        if ([string]::IsNullOrWhiteSpace($guardLog) -and $null -ne $guardDir) {
            $guardLog = Join-Path $guardDir.FullName 'guard.log'
        }

        if ([string]::IsNullOrWhiteSpace($guardState) -and $null -ne $guardDir) {
            $guardState = Join-Path $guardDir.FullName 'guard_state.json'
        }
    }

    Write-Output ("[OPEN-AB-SESSION-GUARD] pid={0} launcher_pid={1} script={2} start_file={3} poll_sec={4} max_b_recovery_attempts={5} recovery_cooldown_minutes={6} guard_log={7} guard_state={8} reuse_existing={9}" -f $processId, $PID, $scriptPath, $StartFile, $PollSec, $MaxBRecoveryAttempts, $RecoveryCooldownMinutes, $guardLog, $guardState, [string]$reuseExisting)
}
finally {
    Exit-LaunchMutex -Context $launchMutexContext
}
