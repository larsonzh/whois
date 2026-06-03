param(
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [ValidateRange(5, 300)][int]$PollSec = 30,
    [switch]$Once,
    [switch]$NoAutoStopOnFinal,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$TriggerCommand = '',
    [switch]$ExecuteTriggerCommand,
    [switch]$SkipHeartbeatPrewarm
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

$existingPids = @(Get-RunningTriggerProcessIdList -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
if ($existingPids.Count -gt 0) {
    Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck existing_count={0} existing_pids={1}" -f $existingPids.Count, ($existingPids -join ','))
    $stoppedPids = @(Invoke-RunningTriggerProcessStop -ProcessIds $existingPids)
    Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
}
else {
    Write-Output '[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck existing_count=0'
}

if (-not $SkipHeartbeatPrewarm.IsPresent) {
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

Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] pid={0} launcher_pid={1} script={2} start_file={3} poll_sec={4} once={5}" -f $processInfo.Id, $PID, $scriptPath, $StartFile, $PollSec, [bool]$Once.IsPresent)
