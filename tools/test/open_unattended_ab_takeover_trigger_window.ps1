param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [ValidateRange(5, 300)][int]$PollSec = 30,
    [switch]$Once,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$TriggerCommand = '',
    [switch]$ExecuteTriggerCommand
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

function Get-RunningTriggerProcessIds {
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

function Stop-RunningTriggerProcesses {
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

$existingPids = @(Get-RunningTriggerProcessIds -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
if ($existingPids.Count -gt 0) {
    Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck existing_count={0} existing_pids={1}" -f $existingPids.Count, ($existingPids -join ','))
    $stoppedPids = @(Stop-RunningTriggerProcesses -ProcessIds $existingPids)
    Write-Output ("[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
}
else {
    Write-Output '[OPEN-AB-TAKEOVER-TRIGGER] restart_precheck existing_count=0'
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
