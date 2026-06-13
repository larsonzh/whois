param(
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [ValidateRange(5, 300)][int]$PollSec = 30,
    [switch]$Once,
    [switch]$NoAutoStopOnFinal,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$TriggerCommand = '',
    [switch]$ExecuteTriggerCommand,
    [switch]$SkipHeartbeatPrewarm,
    [switch]$NoRestartIfRunning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'OPEN-AB-TAKEOVER-TRIGGER'

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

    return [pscustomobject]@{ Name = $name; Mutex = $mutex; Acquired = $acquired }
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

function Get-RunningTriggerProcessIdList {
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
                if (-not $line.Contains('unattended_ab_takeover_trigger.ps1')) {
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

function Invoke-RunningTriggerProcessStop {
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

function Get-SafeToken {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 'default'
    }

    return (([regex]::Replace($Text.Trim(), '[^A-Za-z0-9._-]', '_')).Trim('_'))
}

function Get-StableStartFileToken {
    param([string]$StartFilePath)

    if ([string]::IsNullOrWhiteSpace($StartFilePath)) {
        return 'sf_unknown'
    }

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
        $hashBytes = $sha1.ComputeHash($bytes)
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha1.Dispose()
    }

    return ('sf_{0}' -f $hash)
}

function Get-LegacyStartFileToken {
    param([string]$StartFilePath)

    return Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($StartFilePath).ToLowerInvariant())
}

function Resolve-PreferredDefaultPath {
    param(
        [string]$PreferredPath,
        [string]$LegacyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($LegacyPath) -and -not (Test-Path -LiteralPath $PreferredPath) -and (Test-Path -LiteralPath $LegacyPath)) {
        return $LegacyPath
    }

    return $PreferredPath
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    (Resolve-Path -LiteralPath $StartFile).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $repoRoot $StartFile)).Path
}
$startFileIdentity = Get-NormalizedPathIdentity -Path $startFilePath -RepoRoot $repoRoot
$scriptPath = Join-Path $repoRoot 'tools\test\unattended_ab_takeover_trigger.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$queueRoot = Join-Path $repoRoot 'out\artifacts\ab_agent_queue'
$startFileToken = Get-StableStartFileToken -StartFilePath $startFilePath
$legacyStartFileToken = Get-LegacyStartFileToken -StartFilePath $startFilePath
$triggerLogPath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $startFileToken)) -LegacyPath (Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $legacyStartFileToken))
$triggerStatePath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $startFileToken)) -LegacyPath (Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $legacyStartFileToken))

$launchMutexContext = Enter-LaunchMutex -Role 'takeover-trigger' -StartFilePath $startFilePath
try {
    $existingPids = @(Get-RunningTriggerProcessIdList -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
    $reuseExisting = $false
    $processId = 0

    if ($existingPids.Count -gt 0) {
        if ($NoRestartIfRunning.IsPresent) {
            Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck existing_count={0} existing_pids={1} mode=reuse" -f $existingPids.Count, ($existingPids -join ','))
            $reuseExisting = $true
            $processId = [int]$existingPids[0]
        }
        else {
            Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck existing_count={0} existing_pids={1}" -f $existingPids.Count, ($existingPids -join ','))
            $stoppedPids = @(Invoke-RunningTriggerProcessStop -ProcessIds $existingPids)
            Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
        }
    }
    else {
        Write-Output '[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck existing_count=0'
    }

    if ($reuseExisting) {
        Write-Output '[OPEN-AB-TAKEOVER-TRIGGER] heartbeat_prewarm status=skip reason=reuse-existing'
    }
    elseif (-not $SkipHeartbeatPrewarm.IsPresent) {
        try {
            $startSettings = Read-KeyValueFile -Path $startFilePath
            $heartbeatEnabled = $true
            if ($startSettings.Contains('AI_CHAT_HEARTBEAT_ENABLED')) {
                $heartbeatEnabled = Convert-ToBooleanSetting -Value ([string]$startSettings['AI_CHAT_HEARTBEAT_ENABLED']) -Default $true
            }

            if ($heartbeatEnabled) {
                $heartbeatUpdater = Join-Path $repoRoot 'tools\test\update_chat_session_heartbeat.ps1'
                if (Test-Path -LiteralPath $heartbeatUpdater) {
                    & $powershellPath -NoProfile -ExecutionPolicy Bypass -File $heartbeatUpdater -StartFile $StartFile -Source 'trigger-startup-prewarm' -AsJson | Out-Null
                    Write-Output '[OPEN-AB-TAKEOVER-TRIGGER] heartbeat_prewarm status=ok'
                }
                else {
                    Write-Output ('[OPEN-AB-TAKEOVER-TRIGGER] heartbeat_prewarm status=skip reason=updater-missing path={0}' -f $heartbeatUpdater)
                }
            }
            else {
                Write-Output '[OPEN-AB-TAKEOVER-TRIGGER] heartbeat_prewarm status=skip reason=disabled-by-startfile'
            }
        }
        catch {
            Write-Output ('[OPEN-AB-TAKEOVER-TRIGGER] heartbeat_prewarm status=warn detail={0}' -f $_.Exception.Message)
        }
    }
    else {
        Write-Output '[OPEN-AB-TAKEOVER-TRIGGER] heartbeat_prewarm status=skip reason=flag'
    }

    if (-not $reuseExisting) {
        $argumentList = @(
            '-NoExit',
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $scriptPath,
            '-StartFile', $StartFile,
            '-PollSec', [string]$PollSec
        )

        if ($Once.IsPresent) {
            $argumentList += '-Once'
        }

        if ($NoAutoStopOnFinal.IsPresent) {
            $argumentList += '-NoAutoStopOnFinal'
        }

        if (-not [string]::IsNullOrWhiteSpace($QueuePath)) {
            $argumentList += @('-QueuePath', $QueuePath)
        }

        if (-not [string]::IsNullOrWhiteSpace($TriggerCommand)) {
            $argumentList += @('-TriggerCommand', $TriggerCommand)
        }

        if ($ExecuteTriggerCommand.IsPresent) {
            $argumentList += '-ExecuteTriggerCommand'
        }

        $processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $argumentList -PassThru
        $processId = [int]$processInfo.Id
    }

    Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] pid={0} launcher_pid={1} script={2} start_file={3} poll_sec={4} once={5} trigger_log={6} trigger_state={7} reuse_existing={8}" -f $processId, $PID, $scriptPath, $StartFile, $PollSec, [bool]$Once.IsPresent, $triggerLogPath, $triggerStatePath, [string]$reuseExisting)
}
finally {
    Exit-LaunchMutex -Context $launchMutexContext
}
