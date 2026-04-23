param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 10)][int]$MaxBRecoveryAttempts = 2,
    [ValidateRange(1, 180)][int]$RecoveryCooldownMinutes = 10,
    [bool]$StopOnBudgetExhausted = $true
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

    return (Resolve-Path -LiteralPath (Join-Path $script:RepoRoot $Path)).Path
}

function Convert-ToRepoRelativePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($script:RepoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $Path.Replace('\\', '/')
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

function Get-StartFileMutexName {
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
    return "Local\whois-unattended-{0}-{1}" -f $Role, $hash
}

function Acquire-InstanceMutex {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

    $name = Get-StartFileMutexName -Role $Role -StartFilePath $StartFilePath
    $mutex = New-Object System.Threading.Mutex($false, $name)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }

        if (-not $acquired) {
            Write-Output "[AB-SESSION-GUARD] single_instance_conflict mutex=$name start_file=$StartFilePath"
            $mutex.Dispose()
            throw 'Another unattended_ab_session_guard instance is already active for this start file'
        }
    }
    catch {
        if (-not $acquired -and $null -ne $mutex) {
            try { $mutex.Dispose() } catch {}
        }
        throw
    }

    return $mutex
}

function Read-KeyValueFile {
    param([string]$Path)

    $maxAttempts = 8
    $lines = @()
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                throw
            }

            $delayMs = switch ($attempt) {
                1 { 50 }
                2 { 100 }
                3 { 200 }
                4 { 400 }
                default { 800 }
            }
            Start-Sleep -Milliseconds $delayMs
        }
    }

    $map = [ordered]@{}
    foreach ($line in $lines) {
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

    $maxAttempts = 8
    $sourceLines = @()
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $sourceLines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                throw
            }

            $delayMs = switch ($attempt) {
                1 { 50 }
                2 { 100 }
                3 { 200 }
                4 { 400 }
                default { 800 }
            }
            Start-Sleep -Milliseconds $delayMs
        }
    }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $sourceLines) {
        [void]$lines.Add([string]$line)
    }

    foreach ($key in $Values.Keys) {
        $prefix = "$key="
        $found = $false
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index].StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                $lines[$index] = $prefix + [string]$Values[$key]
                $found = $true
                break
            }
        }

        if (-not $found) {
            [void]$lines.Add($prefix + [string]$Values[$key])
        }
    }

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Set-Content -LiteralPath $Path -Value @($lines) -Encoding utf8 -ErrorAction Stop
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                throw
            }

            $delayMs = switch ($attempt) {
                1 { 50 }
                2 { 100 }
                3 { 200 }
                4 { 400 }
                default { 800 }
            }
            Start-Sleep -Milliseconds $delayMs
        }
    }
}

function Append-DelimitedNote {
    param(
        [AllowEmptyString()][string]$Existing,
        [AllowEmptyString()][string]$Append
    )

    if ([string]::IsNullOrWhiteSpace($Append)) {
        return $Existing
    }

    if ([string]::IsNullOrWhiteSpace($Existing)) {
        return $Append.Trim()
    }

    return ($Existing.TrimEnd() + '; ' + $Append.Trim())
}

function Get-LatestAnchorValueFromNotes {
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

function Resolve-AnchorPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        return Resolve-RepoPath -Path $Path
    }
    catch {
        return ''
    }
}

function Copy-FileIfExists {
    param(
        [AllowEmptyString()][string]$Source,
        [string]$Destination
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Export-FileTail {
    param(
        [AllowEmptyString()][string]$Source,
        [string]$Destination,
        [ValidateRange(1, 2000)][int]$Tail = 400
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    @(Get-Content -LiteralPath $Source -Tail $Tail -ErrorAction SilentlyContinue) | Set-Content -LiteralPath $Destination -Encoding utf8
}

function Write-GuardLog {
    param([string]$Message)

    $line = "[AB-SESSION-GUARD] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    try {
        Add-Content -LiteralPath $script:GuardLogPath -Value $line -Encoding utf8
    }
    catch {
        Write-Warning ("[AB-SESSION-GUARD] log_write_failed path={0}" -f $script:GuardLogPath)
    }
}

function Write-GuardState {
    param([hashtable]$Values)

    foreach ($key in $Values.Keys) {
        $script:GuardState[$key] = $Values[$key]
    }
    $script:GuardState.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $json = $script:GuardState | ConvertTo-Json -Depth 8
    try {
        $json | Set-Content -LiteralPath $script:GuardStatePath -Encoding utf8
    }
    catch {
        Write-Warning ("[AB-SESSION-GUARD] state_write_failed path={0} detail={1}" -f $script:GuardStatePath, $_.Exception.Message)
    }
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Capture-IncidentPackage {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$SessionStatus,
        [string]$AStatus,
        [string]$BStatus
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $incidentDir = Join-Path $script:GuardOutDir ("incident_" + $stamp)
    New-Item -ItemType Directory -Path $incidentDir -Force | Out-Null

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
    $supervisorLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'supervisor_log'
    $companionLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'companion_log'
    $liveStatusAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'live_status'

    $runDir = Resolve-AnchorPath -Path $runDirAnchor
    $supervisorLog = Resolve-AnchorPath -Path $supervisorLogAnchor
    $companionLog = Resolve-AnchorPath -Path $companionLogAnchor
    $liveStatus = Resolve-AnchorPath -Path $liveStatusAnchor

    Copy-FileIfExists -Source $script:StartFilePath -Destination (Join-Path $incidentDir 'start_file_snapshot.md')
    Copy-FileIfExists -Source $liveStatus -Destination (Join-Path $incidentDir 'live_status.json')
    Export-FileTail -Source $supervisorLog -Destination (Join-Path $incidentDir 'supervisor_tail.log') -Tail 500
    Export-FileTail -Source $companionLog -Destination (Join-Path $incidentDir 'companion_tail.log') -Tail 500

    if (-not [string]::IsNullOrWhiteSpace($runDir) -and (Test-Path -LiteralPath $runDir)) {
        Copy-FileIfExists -Source (Join-Path $runDir 'final_status.json') -Destination (Join-Path $incidentDir 'run_final_status.json')
        Copy-FileIfExists -Source (Join-Path $runDir 'final_status.txt') -Destination (Join-Path $incidentDir 'run_final_status.txt')
        Copy-FileIfExists -Source (Join-Path $runDir 'summary.csv') -Destination (Join-Path $incidentDir 'summary.csv')
        Copy-FileIfExists -Source (Join-Path $runDir 'summary_partial.csv') -Destination (Join-Path $incidentDir 'summary_partial.csv')
    }

    $startFileLeaf = [System.IO.Path]::GetFileName($script:StartFilePath).ToLowerInvariant()
    $processSnapshot = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                return ($lineLower -match 'unattended_ab_|start_dev_verify_fastmode_|start_dev_verify_8round_multiround')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object ProcessId
    )
    $processSnapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $incidentDir 'process_snapshot.json') -Encoding utf8

    $gitStatus = @((& git -C $script:RepoRoot status --short 2>&1) | ForEach-Object { [string]$_ })
    $gitStatus | Set-Content -LiteralPath (Join-Path $incidentDir 'git_status_short.txt') -Encoding utf8

    $summary = @(
        "captured_at=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))",
        "session_status=$SessionStatus",
        "a_status=$AStatus",
        "b_status=$BStatus",
        "run_dir_anchor=$runDirAnchor",
        "supervisor_log_anchor=$supervisorLogAnchor",
        "companion_log_anchor=$companionLogAnchor",
        "live_status_anchor=$liveStatusAnchor"
    )
    $summary | Set-Content -LiteralPath (Join-Path $incidentDir 'summary.txt') -Encoding utf8

    return $incidentDir
}

function Invoke-BStageRestart {
    param([int]$Attempt)

    $stageLauncher = Join-Path $script:RepoRoot 'tools\test\open_unattended_ab_stage_window.ps1'
    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    Write-GuardLog ("restart_begin stage=B attempt={0} launcher={1}" -f $Attempt, (Convert-ToRepoRelativePath -Path $stageLauncher))
    $output = @(& $powershellPath -NoProfile -ExecutionPolicy Bypass -File $stageLauncher -Stage B -StartFile $script:StartFilePath -EnableBMonitorRestart 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE

    foreach ($line in $output) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        Write-GuardLog ("restart_output attempt={0} line={1}" -f $Attempt, $line.Trim())
    }

    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Succeeded = ([int]$exitCode -eq 0)
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:StartFilePath = Resolve-RepoPath -Path $StartFile
$script:InstanceMutex = Acquire-InstanceMutex -Role 'session-guard' -StartFilePath $script:StartFilePath

$guardStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:GuardOutDir = Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_session_guard' $guardStamp)
New-Item -ItemType Directory -Path $script:GuardOutDir -Force | Out-Null
$script:GuardLogPath = Join-Path $script:GuardOutDir 'guard.log'
$script:GuardStatePath = Join-Path $script:GuardOutDir 'guard_state.json'
$script:GuardState = [ordered]@{
    schema = 'AB_SESSION_GUARD_STATE_V1'
    status = 'starting'
    start_file = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
    guard_log = (Convert-ToRepoRelativePath -Path $script:GuardLogPath)
    guard_state = (Convert-ToRepoRelativePath -Path $script:GuardStatePath)
    poll_sec = [int]$PollSec
    max_b_recovery_attempts = [int]$MaxBRecoveryAttempts
    recovery_cooldown_minutes = [int]$RecoveryCooldownMinutes
    stop_on_budget_exhausted = [bool]$StopOnBudgetExhausted
    auto_recover_b = $true
    b_recovery_attempts = 0
    last_recovery_at = ''
}

Write-GuardState -Values @{}
Write-GuardLog ("startup start_file={0} poll_sec={1} max_b_recovery_attempts={2} recovery_cooldown_minutes={3} stop_on_budget_exhausted={4} guard_log={5} guard_state={6}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), $PollSec, $MaxBRecoveryAttempts, $RecoveryCooldownMinutes, $StopOnBudgetExhausted, (Convert-ToRepoRelativePath -Path $script:GuardLogPath), (Convert-ToRepoRelativePath -Path $script:GuardStatePath))

$bRecoveryAttempts = 0
$lastRecoveryAt = [datetime]::MinValue
$lastIncidentSignature = ''
$lastHeartbeatAt = [datetime]::MinValue
$lastBudgetExhaustedSignature = ''

try {
    while ($true) {
        try {
            $settings = Read-KeyValueFile -Path $script:StartFilePath

            $sessionStatusRaw = 'NOT_RUN'
            if ($settings.Contains('SESSION_FINAL_STATUS')) {
                $sessionStatusRaw = [string]$settings.SESSION_FINAL_STATUS
            }

            $aStatusRaw = 'NOT_RUN'
            if ($settings.Contains('A_FINAL_STATUS')) {
                $aStatusRaw = [string]$settings.A_FINAL_STATUS
            }

            $bStatusRaw = 'NOT_RUN'
            if ($settings.Contains('B_FINAL_STATUS')) {
                $bStatusRaw = [string]$settings.B_FINAL_STATUS
            }

            $sessionStatus = Get-StatusValue -Value $sessionStatusRaw
            $aStatus = Get-StatusValue -Value $aStatusRaw
            $bStatus = Get-StatusValue -Value $bStatusRaw

            $autoRecoverB = $true
            if ($settings.Contains('LOCAL_GUARD_AUTO_RECOVER_B')) {
                $autoRecoverB = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AUTO_RECOVER_B) -Default $true
            }

            if ($settings.Contains('LOCAL_GUARD_MAX_B_RECOVERY_ATTEMPTS')) {
                $parsedAttempts = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_MAX_B_RECOVERY_ATTEMPTS), [ref]$parsedAttempts)) {
                    if ($parsedAttempts -ge 0 -and $parsedAttempts -le 10) {
                        $MaxBRecoveryAttempts = $parsedAttempts
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_RECOVERY_COOLDOWN_MINUTES')) {
                $parsedCooldown = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_RECOVERY_COOLDOWN_MINUTES), [ref]$parsedCooldown)) {
                    if ($parsedCooldown -ge 1 -and $parsedCooldown -le 180) {
                        $RecoveryCooldownMinutes = $parsedCooldown
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_POLL_SEC')) {
                $parsedPoll = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_POLL_SEC), [ref]$parsedPoll)) {
                    if ($parsedPoll -ge 15 -and $parsedPoll -le 300) {
                        $PollSec = $parsedPoll
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_STOP_ON_BUDGET_EXHAUSTED')) {
                $StopOnBudgetExhausted = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_STOP_ON_BUDGET_EXHAUSTED) -Default $true
            }

            $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
            $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
            $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'

            $guardLoopStatus = 'idle'
            if ($running) {
                $guardLoopStatus = 'running'
            }

            $lastRecoveryAtText = ''
            if ($lastRecoveryAt -ne [datetime]::MinValue) {
                $lastRecoveryAtText = $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
            }

            Write-GuardState -Values @{
                status = $guardLoopStatus
                session_final_status = $sessionStatus
                a_final_status = $aStatus
                b_final_status = $bStatus
                run_dir = $runDirAnchor
                poll_sec = [int]$PollSec
                max_b_recovery_attempts = [int]$MaxBRecoveryAttempts
                recovery_cooldown_minutes = [int]$RecoveryCooldownMinutes
                stop_on_budget_exhausted = [bool]$StopOnBudgetExhausted
                auto_recover_b = [bool]$autoRecoverB
                b_recovery_attempts = [int]$bRecoveryAttempts
                last_recovery_at = $lastRecoveryAtText
            }

            if ($sessionStatus -eq 'PASS' -and -not $running) {
                Write-GuardLog ("complete session_status=PASS a={0} b={1}" -f $aStatus, $bStatus)
                break
            }

            if (($sessionStatus -in @('FAIL', 'BLOCKED')) -and -not $running) {
                $statusSignature = "{0}|{1}|{2}|{3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor
                if ($statusSignature -ne $lastIncidentSignature) {
                    $incidentDir = Capture-IncidentPackage -Settings $settings -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                    $incidentRel = Convert-ToRepoRelativePath -Path $incidentDir
                    $lastIncidentSignature = $statusSignature
                    Write-GuardLog ("incident status={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)

                    $newNotes = Append-DelimitedNote -Existing $notes -Append ("guard_incident status={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)
                    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                        SESSION_FINAL_NOTES = $newNotes
                    }
                }

                $canRecoverB = ($aStatus -eq 'PASS' -and $bStatus -in @('FAIL', 'BLOCKED'))
                if ($autoRecoverB -and $canRecoverB) {
                    if ($bRecoveryAttempts -ge $MaxBRecoveryAttempts) {
                        $budgetSignature = "{0}|{1}|{2}|{3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor
                        if ($budgetSignature -ne $lastBudgetExhaustedSignature) {
                            Write-GuardLog ("recovery_skip reason=budget_exhausted attempts={0} max={1}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts)
                            $lastBudgetExhaustedSignature = $budgetSignature
                        }

                        if ($StopOnBudgetExhausted) {
                            Write-GuardState -Values @{
                                status = 'stopped'
                                event = 'budget-exhausted'
                                stop_reason = 'budget-exhausted'
                                b_recovery_attempts = [int]$bRecoveryAttempts
                            }
                            Write-GuardLog ("complete reason=budget_exhausted attempts={0} max={1} stop_on_budget_exhausted={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $StopOnBudgetExhausted)
                            break
                        }
                    }
                    elseif ($lastRecoveryAt -ne [datetime]::MinValue -and ((Get-Date) -lt $lastRecoveryAt.AddMinutes($RecoveryCooldownMinutes))) {
                        $lastBudgetExhaustedSignature = ''
                        $nextAt = $lastRecoveryAt.AddMinutes($RecoveryCooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss')
                        Write-GuardLog ("recovery_skip reason=cooldown next_at={0}" -f $nextAt)
                    }
                    else {
                        $lastBudgetExhaustedSignature = ''
                        $attempt = $bRecoveryAttempts + 1
                        $restartResult = Invoke-BStageRestart -Attempt $attempt
                        if ($restartResult.Succeeded) {
                            $bRecoveryAttempts = $attempt
                            $lastRecoveryAt = Get-Date
                            $lastIncidentSignature = ''
                            $lastBudgetExhaustedSignature = ''
                            Write-GuardState -Values @{
                                status = 'running'
                                last_action = 'restart-triggered'
                                b_recovery_attempts = [int]$bRecoveryAttempts
                                last_recovery_at = $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
                            }
                            $restartNote = "guard_recovery action=restart-b attempt={0} at={1}" -f $attempt, $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
                            $newNotes = Append-DelimitedNote -Existing ([string](Read-KeyValueFile -Path $script:StartFilePath).SESSION_FINAL_NOTES) -Append $restartNote
                            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{ SESSION_FINAL_NOTES = $newNotes }
                            Write-GuardLog ("recovery_triggered stage=B attempt={0}" -f $attempt)
                            Start-Sleep -Seconds 5
                            continue
                        }

                        Write-GuardLog ("recovery_failed stage=B attempt={0} exit_code={1}" -f $attempt, $restartResult.ExitCode)
                    }
                }
                else {
                    $lastBudgetExhaustedSignature = ''
                    Write-GuardLog ("manual_action_required status={0} a={1} b={2} auto_recover_b={3}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB)
                }
            }
            else {
                $lastBudgetExhaustedSignature = ''
                $now = Get-Date
                if ($lastHeartbeatAt -eq [datetime]::MinValue -or (($now - $lastHeartbeatAt).TotalMinutes -ge 5)) {
                    Write-GuardLog ("heartbeat session={0} a={1} b={2} running={3} run_dir={4}" -f $sessionStatus, $aStatus, $bStatus, $running, $runDirAnchor)
                    $lastHeartbeatAt = $now
                }
            }
        }
        catch {
            Write-GuardLog ("loop_error detail={0}" -f $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' '))
        }

        Start-Sleep -Seconds $PollSec
    }
}
finally {
    Write-GuardState -Values @{
        status = 'stopped'
        event = 'shutdown'
    }
    Write-GuardLog ("shutdown_pid pid={0}" -f $PID)
    if ($null -ne $script:InstanceMutex) {
        try {
            $script:InstanceMutex.ReleaseMutex() | Out-Null
        }
        catch {
        }
        finally {
            $script:InstanceMutex.Dispose()
        }
    }
}