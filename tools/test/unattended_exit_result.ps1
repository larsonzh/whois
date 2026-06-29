Set-StrictMode -Version Latest

function Test-RoleProcessTrulyAlive {
    param(
        [string]$Role,
        [object[]]$Processes,
        [string]$RepoRoot
    )

    foreach ($proc in @($Processes)) {
        $cmdLine = [string]$proc.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmdLine)) { continue }

        # Derive state file path from role and start-file
        $roleStateRoot = switch ($Role) {
            'guard'      { Join-Path $RepoRoot 'out\artifacts\ab_session_guard' }
            'supervisor' { Join-Path $RepoRoot 'out\artifacts\ab_supervisor' }
            'trigger'    { Join-Path $RepoRoot 'out\artifacts\ab_agent_queue' }
            'companion'  { Join-Path $RepoRoot 'out\artifacts\ab_companion' }
            default      { '' }
        }
        if ([string]::IsNullOrWhiteSpace($roleStateRoot)) { return $true }  # unknown role: assume alive

        # Find the state file by scanning for the latest timestamped directory
        $stateFileName = switch ($Role) {
            'guard'      { 'guard_state.json' }
            'supervisor' { 'live_status.json' }
            'companion'  { 'companion.log' }
            'trigger'    { $null }  # handled separately below
        }

        $statePath = ''
        if ($Role -eq 'trigger') {
            # Trigger: extract start-file hash from any matching process command line
            $sfMatch = [regex]::Match($cmdLine, '-StartFile\s+"([^"]+)"')
            if (-not $sfMatch.Success) { $sfMatch = [regex]::Match($cmdLine, '-StartFile\s+(\S+)') }
            if ($sfMatch.Success) {
                $triggerStartFile = $sfMatch.Groups[1].Value
                $fullPath = [System.IO.Path]::GetFullPath($triggerStartFile).ToLowerInvariant()
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
                $sha1 = [System.Security.Cryptography.SHA1]::Create()
                try {
                    $hashBytes = $sha1.ComputeHash($bytes)
                }
                finally {
                    $sha1.Dispose()
                }
                $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
                $statePath = Join-Path $roleStateRoot "takeover_trigger_state_sf_$hash.json"
            }
            if ([string]::IsNullOrWhiteSpace($statePath) -or -not (Test-Path -LiteralPath $statePath)) {
                return $true  # Can't find state file, assume alive
            }
        }
        else {
            # Guard / supervisor: scan for the latest timestamped subdirectory
            if (Test-Path -LiteralPath $roleStateRoot) {
                $dirs = @(Get-ChildItem -LiteralPath $roleStateRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^\d{8}-\d{6}$' } |
                    Sort-Object LastWriteTime -Descending)
                foreach ($dir in $dirs) {
                    $candidate = Join-Path $dir.FullName $stateFileName
                    if (Test-Path -LiteralPath $candidate) {
                        $statePath = $candidate
                        break
                    }
                }
            }
            if ([string]::IsNullOrWhiteSpace($statePath)) {
                return $true  # No state file found, assume alive
            }
        }

        # Read state file and check for terminal markers
        try {
            $rawState = Get-Content -LiteralPath $statePath -Raw -Encoding utf8 -ErrorAction SilentlyContinue
            if (-not [string]::IsNullOrWhiteSpace($rawState)) {
                $lowerState = $rawState.ToLowerInvariant()
                if ($lowerState.Contains('"status": "stopped"') -or
                    $lowerState.Contains('"status": "shutdown"') -or
                    $lowerState.Contains('"event": "shutdown"')) {
                    continue  # This instance terminated, check next process
                }
            }
        }
        catch { }

        # For companion: check log staleness (companion heartbeats every ~60s, treat >180s as dead)
        if ($Role -eq 'companion') {
            $now = Get-Date
            $logAge = ($now - (Get-Item -LiteralPath $statePath -ErrorAction SilentlyContinue).LastWriteTime).TotalSeconds
            if ($logAge -gt 180) {
                continue  # Companion log stale -> script terminated, treat as zombie
            }
        }

        # Found an alive process
        return $true
    }

    return $false  # All matching processes appear to be zombies
}

function Invoke-MonitorChainHealthCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Roles,
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$StartFilePath,
        [string]$LogPrefix = 'health_check'
    )

    $roleMap = @(
        @{ n = 'companion';  p = 'tools/test/open_unattended_ab_companion_window.ps1' }
        @{ n = 'supervisor'; p = 'tools/test/open_unattended_ab_supervisor_window.ps1' }
        @{ n = 'guard';      p = 'tools/test/open_unattended_ab_session_guard_window.ps1' }
        @{ n = 'trigger';    p = 'tools/test/open_unattended_ab_takeover_trigger_window.ps1' }
    )

    # Normalize start file identity for single-instance matching
    $startFileIdentity = try {
        $resolved = if ([System.IO.Path]::IsPathRooted($StartFilePath)) {
            [System.IO.Path]::GetFullPath($StartFilePath)
        }
        else {
            [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $StartFilePath))
        }
        $resolved.ToLowerInvariant()
    } catch { '' }

    foreach ($role in $Roles) {
        $rn = $role.Trim().ToLowerInvariant()
        $entry = $roleMap | Where-Object { $_.n -eq $rn } | Select-Object -First 1
        if ($null -eq $entry) { continue }

        $scriptLeaf = ('unattended_ab_{0}.ps1' -f $rn)
        $found = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object {
            $procCmdLine = [string]$_.CommandLine
            if ([string]::IsNullOrWhiteSpace($procCmdLine)) { return $false }
            if (-not $procCmdLine.ToLowerInvariant().Contains($scriptLeaf)) { return $false }
            if ([string]::IsNullOrWhiteSpace($startFileIdentity)) { return $true }

            # Single-instance check: filter by start file identity
            $sfMatch = [regex]::Match($procCmdLine, '-StartFile\s+"([^"]+)"')
            if (-not $sfMatch.Success) { $sfMatch = [regex]::Match($procCmdLine, '-StartFile\s+(\S+)') }
            if (-not $sfMatch.Success) { return $false }

            $procStartFile = $sfMatch.Groups[1].Value
            $procStartFileNormalized = try { [System.IO.Path]::GetFullPath($procStartFile).ToLowerInvariant() } catch { return $false }
            return ($procStartFileNormalized -eq $startFileIdentity)
        })

        if (@($found).Count -gt 0) {
            # PID found — verify it's not a zombie (script terminated but -NoExit shell alive).
            # Check known state files for terminal markers.
            $trulyAlive = Test-RoleProcessTrulyAlive -Role $rn -Processes $found -RepoRoot $RepoRoot
            if (-not $trulyAlive) {
                Write-Output ("[{0}] role={1} action=zombie-detected count={2}" -f $LogPrefix, $rn, @($found).Count)
                $found = @()  # Force restart below
            }
        }

        if (@($found).Count -eq 0) {
            $launcherPath = Join-Path $RepoRoot ([string]$entry.p)
            if (Test-Path -LiteralPath $launcherPath) {
                try {
                    Start-Process -WindowStyle Hidden -FilePath 'powershell' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`" -StartFile `"$StartFilePath`" -NoRestartIfRunning"
                    Write-Output ("[{0}] role={1} action=restart" -f $LogPrefix, $rn)
                }
                catch {
                    Write-Output ("[{0}] role={1} action=restart_failed detail={2}" -f $LogPrefix, $rn, $_.Exception.Message)
                }
            }
        }
    }
}

function Invoke-KillOldRoleInstances {
    param(
        [string]$Role,
        [string]$StartFilePath,
        [string]$LogPrefix = '[AB-MONITOR]'
    )

    $scriptName = switch ($Role) {
        'supervisor' { 'unattended_ab_supervisor.ps1' }
        'companion'  { 'unattended_ab_companion.ps1' }
        'guard'      { 'unattended_ab_session_guard.ps1' }
        'trigger'    { 'unattended_ab_takeover_trigger.ps1' }
        default      { '' }
    }

    if ([string]::IsNullOrWhiteSpace($scriptName)) {
        Write-Output ("${LogPrefix} kill_old_instances role={0} script_name=unknown skipped" -f $Role)
        return
    }

    $killedCount = 0
    try {
        $candidates = @(Get-Process -Name 'powershell' -ErrorAction SilentlyContinue | Where-Object { -not $_.HasExited })
        foreach ($candidate in $candidates) {
            if ($candidate.Id -eq $PID) { continue }
            try {
                $cmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($candidate.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmdLine -match [regex]::Escape($scriptName)) {
                    $consolePid = $candidate.Id
                    try {
                        $processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $consolePid" -ErrorAction SilentlyContinue
                        if ($processInfo) {
                            $parentPid = [int]$processInfo.ParentProcessId
                            try {
                                $parentProcess = Get-Process -Id $parentPid -ErrorAction SilentlyContinue
                                if ($parentProcess -and $parentProcess.ProcessName -eq 'powershell' -and -not $parentProcess.HasExited) {
                                    Stop-Process -Id $parentPid -Force -ErrorAction SilentlyContinue
                                    Write-Output ("${LogPrefix} kill_old_instances role={0} old_pid={1} console_pid={2} action=killed-console" -f $Role, $candidate.Id, $parentPid)
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                    Stop-Process -Id $candidate.Id -Force -ErrorAction SilentlyContinue
                    $killedCount++
                    Write-Output ("${LogPrefix} kill_old_instances role={0} old_pid={1} action=killed-process" -f $Role, $candidate.Id)
                }
            }
            catch { }
        }
    }
    catch { }

    if ($killedCount -gt 0) {
        Start-Sleep -Seconds 2
    }

    Write-Output ("${LogPrefix} kill_old_instances role={0} killed_count={1}" -f $Role, $killedCount)
}

function Get-UnattendedExitCodeFromRecord {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record,
        [int]$DefaultExitCode = 1
    )

    $exitCode = if ($DefaultExitCode -gt 0) { [int]$DefaultExitCode } else { 1 }
    $detail = ''
    if ($null -ne $Record -and $null -ne $Record.Exception) {
        $detail = [string]$Record.Exception.Message
    }

    $normalized = $detail.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $exitCode
    }

    if ($normalized -match 'path must not be empty|must be an integer within|missing script|not found|cannot find path|because it does not exist|is missing in start file') {
        return 2
    }

    if ($normalized -match 'a_only_guard blocked|precheck gate blocked|launch-ready gate blocked|start gate blocked|task static precheck failed') {
        return 3
    }

    if ($normalized -match 'stage_delegate_failed') {
        return 4
    }

    return $exitCode
}

function Write-UnattendedUnhandledResult {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record,
        [int]$ExitCode = 1
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'UNATTENDED-SCRIPT'
    }

    $detail = if ($null -ne $Record -and $null -ne $Record.Exception) {
        [string]$Record.Exception.Message
    }
    else {
        'unknown-error'
    }

    $detail = ([regex]::Replace($detail, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = 'unknown-error'
    }

    if ($ExitCode -le 0) {
        $ExitCode = 1
    }

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code={1} error={2}" -f $Tag, $ExitCode, $detail)
}

function Exit-UnattendedFailure {
    param(
        [string]$Tag,
        [string]$Reason,
        [int]$ExitCode = 1
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'UNATTENDED-SCRIPT'
    }

    $detail = ([regex]::Replace([string]$Reason, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = 'script-failed'
    }

    if ($ExitCode -le 0) {
        $ExitCode = 1
    }

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code={1} error={2}" -f $Tag, $ExitCode, $detail)
    exit $ExitCode
}
