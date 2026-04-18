param(
    [Parameter(Mandatory = $true)][int]$ProtectedRootPid,
    [Parameter(Mandatory = $true)][string]$SessionOutDir,
    [ValidateSet("safe")][string]$Mode = "safe",
    [ValidateRange(30, 900)][int]$IntervalSec = 120,
    [ValidateRange(60, 7200)][int]$MinAgeSec = 600,
    [switch]$RunOnce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SessionOutDir)) {
    New-Item -ItemType Directory -Path $SessionOutDir -Force | Out-Null
}

$logFile = Join-Path $SessionOutDir "terminal_watchdog.log"
$completionFile = Join-Path $SessionOutDir "final_status.txt"
$currentWatchdogPid = $PID

function Write-WatchdogLog {
    param([string]$Message)

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[TERM-WATCHDOG] timestamp=$timestamp pid=$currentWatchdogPid mode=$Mode $Message"
    Add-Content -LiteralPath $logFile -Value $line -Encoding utf8
}

function Get-ProcessMap {
    $map = @{}
    foreach ($processInfo in @(Get-CimInstance Win32_Process)) {
        $map[[int]$processInfo.ProcessId] = $processInfo
    }

    return $map
}

function Get-ChildMap {
    param([hashtable]$ProcessMap)

    $childMap = @{}
    foreach ($processInfo in $ProcessMap.Values) {
        $parentPid = [int]$processInfo.ParentProcessId
        if (-not $childMap.ContainsKey($parentPid)) {
            $childMap[$parentPid] = @()
        }
        $childMap[$parentPid] += [int]$processInfo.ProcessId
    }

    return $childMap
}

function Get-DescendantIds {
    param(
        [int]$RootPid,
        [hashtable]$ChildMap
    )

    $queue = New-Object 'System.Collections.Generic.Queue[int]'
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $queue.Enqueue($RootPid)
    [void]$seen.Add($RootPid)

    while ($queue.Count -gt 0) {
        $targetPid = $queue.Dequeue()
        if (-not $ChildMap.ContainsKey($targetPid)) {
            continue
        }

        foreach ($childPid in @($ChildMap[$targetPid])) {
            $resolvedChildPid = [int]$childPid
            if ($seen.Add($resolvedChildPid)) {
                $queue.Enqueue($resolvedChildPid)
            }
        }
    }

    return @($seen)
}

function Get-ProcessAgeSec {
    param([int]$TargetPid)

    try {
        $processInfo = Get-Process -Id $TargetPid -ErrorAction Stop
        return [int][Math]::Floor(((Get-Date) - $processInfo.StartTime).TotalSeconds)
    }
    catch {
        return -1
    }
}

function Test-IsShellIntegrationPowerShell {
    param([string]$CommandLine)

    return ($CommandLine -like "*shellIntegration.ps1*" -and $CommandLine -notlike "*PowerShellEditorServices*")
}

function Test-IsShellIntegrationBash {
    param([string]$CommandLine)

    return ($CommandLine -like "*shellIntegration-bash.sh*")
}

function Get-SummaryPartialState {
    $summaryFile = Join-Path $SessionOutDir "summary_partial.csv"
    if (-not (Test-Path -LiteralPath $summaryFile)) {
        return "missing"
    }

    $ageSec = [Math]::Round(((Get-Date) - (Get-Item -LiteralPath $summaryFile).LastWriteTime).TotalSeconds, 1)
    return "age_sec=$ageSec"
}

function Invoke-WatchdogCycle {
    if (Test-Path -LiteralPath $completionFile) {
        Write-WatchdogLog "state=stop reason=final-status-detected"
        return "stop"
    }

    $processMap = Get-ProcessMap
    if (-not $processMap.ContainsKey($ProtectedRootPid)) {
        Write-WatchdogLog "state=stop reason=protected-root-missing"
        return "stop"
    }

    $childMap = Get-ChildMap -ProcessMap $processMap
    $protectedPidSet = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($protectedPid in @(Get-DescendantIds -RootPid $ProtectedRootPid -ChildMap $childMap)) {
        [void]$protectedPidSet.Add([int]$protectedPid)
    }

    [void]$protectedPidSet.Add($currentWatchdogPid)
    if ($processMap.ContainsKey($currentWatchdogPid)) {
        $watchdogParentPid = [int]$processMap[$currentWatchdogPid].ParentProcessId
        if ($watchdogParentPid -gt 0) {
            [void]$protectedPidSet.Add($watchdogParentPid)
        }
    }

    $killPidSet = New-Object 'System.Collections.Generic.HashSet[int]'
    $candidateTags = New-Object System.Collections.Generic.List[string]

    foreach ($processInfo in $processMap.Values) {
        $targetPid = [int]$processInfo.ProcessId
        if ($protectedPidSet.Contains($targetPid)) {
            continue
        }

        $ageSec = Get-ProcessAgeSec -TargetPid $targetPid
        if ($ageSec -lt 0 -or $ageSec -lt $MinAgeSec) {
            continue
        }

        $commandLine = [string]$processInfo.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            continue
        }

        $childCount = if ($childMap.ContainsKey($targetPid)) { @($childMap[$targetPid]).Count } else { 0 }
        $processName = [string]$processInfo.Name

        if ($processName -ieq "powershell.exe" -and (Test-IsShellIntegrationPowerShell -CommandLine $commandLine) -and $childCount -eq 0) {
            [void]$killPidSet.Add($targetPid)
            [void]$candidateTags.Add("powershell:$targetPid")
            continue
        }

        if ($processName -ieq "bash.exe" -and (Test-IsShellIntegrationBash -CommandLine $commandLine)) {
            foreach ($treePid in @(Get-DescendantIds -RootPid $targetPid -ChildMap $childMap)) {
                $resolvedTreePid = [int]$treePid
                if (-not $protectedPidSet.Contains($resolvedTreePid)) {
                    [void]$killPidSet.Add($resolvedTreePid)
                }
            }

            [void]$killPidSet.Add($targetPid)
            [void]$candidateTags.Add("bash:$targetPid")
        }
    }

    foreach ($processInfo in $processMap.Values) {
        $targetPid = [int]$processInfo.ProcessId
        if ($protectedPidSet.Contains($targetPid) -or $killPidSet.Contains($targetPid)) {
            continue
        }

        if ([string]$processInfo.Name -ne "conhost.exe") {
            continue
        }

        $ageSec = Get-ProcessAgeSec -TargetPid $targetPid
        if ($ageSec -lt 0 -or $ageSec -lt $MinAgeSec) {
            continue
        }

        $parentPid = [int]$processInfo.ParentProcessId
        $commandLine = [string]$processInfo.CommandLine
        if ($killPidSet.Contains($parentPid) -and $commandLine -like "*--headless*") {
            [void]$killPidSet.Add($targetPid)
            [void]$candidateTags.Add("conhost:$targetPid")
        }
    }

    $summaryState = Get-SummaryPartialState
    if ($killPidSet.Count -eq 0) {
        Write-WatchdogLog "state=heartbeat summary_partial=$summaryState killed=0"
        return "continue"
    }

    $killOrder = @($killPidSet | ForEach-Object {
        [pscustomobject]@{
            Pid = [int]$_
            AgeSec = Get-ProcessAgeSec -TargetPid ([int]$_)
        }
    } | Sort-Object AgeSec -Descending, Pid -Descending)

    $killedPids = @()
    $failedPids = @()
    foreach ($entry in $killOrder) {
        Stop-Process -Id $entry.Pid -Force -ErrorAction SilentlyContinue
        if (Get-Process -Id $entry.Pid -ErrorAction SilentlyContinue) {
            $failedPids += [string]$entry.Pid
        }
        else {
            $killedPids += [string]$entry.Pid
        }
    }

    $candidateText = if ($candidateTags.Count -eq 0) { "none" } else { ($candidateTags -join ",") }
    $killedText = if ($killedPids.Count -eq 0) { "none" } else { ($killedPids -join ",") }
    $failedText = if ($failedPids.Count -eq 0) { "none" } else { ($failedPids -join ",") }
    Write-WatchdogLog "state=cleanup summary_partial=$summaryState candidates=$candidateText killed=$killedText failed=$failedText"
    return "continue"
}

Write-WatchdogLog "state=start protected_root_pid=$ProtectedRootPid interval_sec=$IntervalSec min_age_sec=$MinAgeSec session_out_dir=$SessionOutDir"

$stopReason = "run-once"
while ($true) {
    $cycleResult = Invoke-WatchdogCycle
    if ($RunOnce.IsPresent) {
        if ($cycleResult -ne "continue") {
            $stopReason = $cycleResult
        }
        break
    }

    if ($cycleResult -ne "continue") {
        $stopReason = $cycleResult
        break
    }

    Start-Sleep -Seconds $IntervalSec
}

Write-WatchdogLog "state=stop reason=$stopReason"