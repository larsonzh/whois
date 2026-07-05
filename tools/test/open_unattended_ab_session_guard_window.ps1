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
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'OPEN-AB-SESSION-GUARD'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

function Test-ExistingMonitorProcessAlive {
    param(
        [int[]]$ProcessIds,
        [string[]]$EvidencePaths
    )

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

    foreach ($path in @($EvidencePaths)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
            continue
        }

        $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            continue
        }

        # PID is alive; check JSON state file for explicit shutdown markers.
        # Skip stale-age threshold because a live process may have an idle
        # state file during quiet periods — don't mistake it for a zombie.
        if ($path -like '*.json') {
            try {
                $rawTerminal = Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace($rawTerminal)) {
                    $lowerTerminal = $rawTerminal.ToLowerInvariant()
                    $terminalPatterns = @('"status": "stopped"', '"status": "shutdown"', '"event": "shutdown"')
                    $hasTerminal = $false
                    foreach ($tp in $terminalPatterns) {
                        if ($lowerTerminal.Contains($tp)) {
                            $hasTerminal = $true
                            break
                        }
                    }
                    if ($hasTerminal) {
                        continue
                    }
                }
            }
            catch { $null = $_ }
        }
        return $true
    }

    return $false
}

function Clear-OrphanedMonitorConsole {
    param(
        [string]$Role,
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fullPath))
            $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').Substring(0, 12).ToLowerInvariant()
        }
        finally { $sha1.Dispose() }
        $titlePattern = "whois-mon-$Role-$hash*"

        $orphanedConhostPids = New-Object 'System.Collections.Generic.List[int]'
        $allConhost = @(Get-CimInstance Win32_Process -Filter "Name='conhost.exe'" -ErrorAction SilentlyContinue)
        foreach ($ch in $allConhost) {
            $chPid = [int]$ch.ProcessId
            $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$chPid" -ErrorAction SilentlyContinue)
            $hasMatchingAlive = $false
            $hasMatchingExited = $false
            foreach ($child in $children) {
                if ($child.Name -eq 'powershell.exe') {
                    $cmdLine = [string]$child.CommandLine
                    if ($cmdLine -match [regex]::Escape("-$Role")) {
                        try {
                            $null = Get-Process -Id ([int]$child.ProcessId) -ErrorAction Stop
                            $hasMatchingAlive = $true
                        }
                        catch {
                            $hasMatchingExited = $true
                        }
                    }
                }
            }
            if ($hasMatchingExited -and -not $hasMatchingAlive) {
                $orphanedConhostPids.Add($chPid)
            }
        }

        $null = & 'taskkill.exe' '/F', '/FI', ("WINDOWTITLE eq $titlePattern") 2>&1

        foreach ($targetPid in $orphanedConhostPids) {
            $null = & 'taskkill.exe' '/F', '/PID', ([string]$targetPid) 2>&1
        }
    }
    catch { $null = $_ }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    (Resolve-Path -LiteralPath $StartFile).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $repoRoot $StartFile)).Path
}
$settings = Read-KeyValueFileLastWins -Path $startFilePath
$startFileIdentity = Get-NormalizedPathIdentity -Path $startFilePath -RepoRoot $repoRoot
$scriptPath = Join-Path $repoRoot 'tools\test\unattended_ab_session_guard.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$launchMutexContext = Enter-LaunchMutex -Role 'session-guard' -StartFilePath $startFilePath
try {
    $existingPids = @(Get-RunningStartFileProcessIdList -ScriptLeaf 'unattended_ab_session_guard.ps1' -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
    $reuseExisting = $false
    $processId = 0

    if ($existingPids.Count -gt 0) {
        # Check whether the existing process is a live monitor or an empty shell
        # by inspecting guard_state.json for terminal markers.
        $isTrulyAlive = $true
        $guardStatePath = ''
        $guardLogPath = Get-AnchorValueFromConfig -Settings $settings -Key 'guard_log'
        if (-not [string]::IsNullOrWhiteSpace($guardLogPath)) {
            $guardStatePath = Join-Path (Split-Path -Parent (Join-Path $repoRoot $guardLogPath)) 'guard_state.json'
        }
        # Fallback to latest timestamped guard_state.json when anchor is missing
        if ([string]::IsNullOrWhiteSpace($guardStatePath) -or -not (Test-Path -LiteralPath $guardStatePath)) {
            $gdRoot = Join-Path $repoRoot 'out\artifacts\ab_session_guard'
            if (Test-Path -LiteralPath $gdRoot) {
                $gdDir = Get-LatestTimestampedDirectory -Root $gdRoot -After ([datetime]::MinValue)
                if ($null -ne $gdDir) {
                    $candidate = Join-Path $gdDir.FullName 'guard_state.json'
                    if (Test-Path -LiteralPath $candidate) { $guardStatePath = $candidate }
                }
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($guardStatePath)) {
            try {
                $rawState = Get-Content -LiteralPath $guardStatePath -Raw -Encoding utf8 -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace($rawState)) {
                    $lowerState = $rawState.ToLowerInvariant()
                    if ($lowerState -match '"status":\s+"stopped"' -or
                            $lowerState -match '"status":\s+"shutdown"' -or
                            $lowerState -match '"event":\s+"shutdown"') {
                        $isTrulyAlive = $false
                    }
                }
            } catch { $null = $_ }
        }
        if ($isTrulyAlive) {
            $modeTag = if ($NoRestartIfRunning) { 'no-restart-running' } else { 'reuse-existing' }
            Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck existing_count={0} existing_pids={1} mode={2}" -f $existingPids.Count, ($existingPids -join ','), $modeTag)
            $reuseExisting = $true
            $processId = [int]$existingPids[0]
        }
        else {
            Write-Output ("[OPEN-AB-SESSION-GUARD] restart_precheck existing_count={0} existing_pids={1} mode=empty-shell-clean" -f $existingPids.Count, ($existingPids -join ','))
            Invoke-RunningProcessStop -ProcessIds $existingPids -UseTaskkill -TaskkillGraceMs 1500 -WaitTimeoutSec 15
            Clear-OrphanedMonitorConsole -Role 'session-guard' -StartFilePath $startFilePath -RepoRoot $repoRoot
        }
    }

    if (-not $reuseExisting) {
        Clear-OrphanedMonitorConsole -Role 'session-guard' -StartFilePath $startFilePath -RepoRoot $repoRoot
        Write-Output '[OPEN-AB-SESSION-GUARD] restart_precheck existing_count=0'
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

exit 0
