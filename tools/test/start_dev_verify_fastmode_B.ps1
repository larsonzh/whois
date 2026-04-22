param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TaskDefinitionFileName
)

$ErrorActionPreference = "Stop"

function Get-RepoScopedMutexName {
    param(
        [string]$Role,
        [string]$RepoRoot
    )

    $fullPath = [System.IO.Path]::GetFullPath($RepoRoot).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Local\whois-fastmode-$Role-$hash"
}

function Acquire-RunMutex {
    param(
        [string]$Role,
        [string]$RepoRoot
    )

    $name = Get-RepoScopedMutexName -Role $Role -RepoRoot $RepoRoot
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
            $mutex.Dispose()
            throw "Another $Role fastmode run is already active in this repository."
        }
    }
    catch {
        if (-not $acquired -and $null -ne $mutex) {
            try {
                $mutex.Dispose()
            }
            catch {
            }
        }
        throw
    }

    return [pscustomobject]@{
        Name = $name
        Mutex = $mutex
    }
}

function Get-RunningFastmodeProcessIds {
    param(
        [string]$Role,
        [string]$RepoRoot,
        [int]$ExcludePid
    )

    $scriptLeaf = ("start_dev_verify_fastmode_{0}.ps1" -f $Role).ToLowerInvariant()
    $scriptPath = (Join-Path $PSScriptRoot ("start_dev_verify_fastmode_{0}.ps1" -f $Role)).ToLowerInvariant()
    $scriptPathSlash = $scriptPath.Replace('\', '/')
    $repoRootWindows = $RepoRoot.ToLowerInvariant()
    $repoRootSlash = $repoRootWindows.Replace('\', '/')

    $ids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $processId = [int]$_.ProcessId
                if ($processId -eq $ExcludePid) {
                    return $false
                }

                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if (-not $line.Contains($scriptLeaf)) {
                    return $false
                }

                return $line.Contains($scriptPath) -or $line.Contains($scriptPathSlash) -or $line.Contains($repoRootWindows) -or $line.Contains($repoRootSlash)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    return @($ids)
}

function Stop-RunningFastmodeProcesses {
    param([int[]]$ProcessIds)

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($targetPid in @($ProcessIds | Sort-Object -Unique)) {
        if ($targetPid -le 0) {
            continue
        }

        try {
            Stop-Process -Id $targetPid -Force -ErrorAction Stop
            Wait-Process -Id $targetPid -Timeout 30 -ErrorAction SilentlyContinue
            [void]$stopped.Add([int]$targetPid)
        }
        catch {
        }
    }

    return @($stopped)
}

function Resolve-TaskDefinitionRelativePath {
    param([string]$InputName)

    if ([string]::IsNullOrWhiteSpace($InputName)) {
        throw "TaskDefinitionFileName is required."
    }

    $normalized = $InputName.Trim().Replace("\\", "/")
    if ($normalized.StartsWith("./")) {
        $normalized = $normalized.Substring(2)
    }

    if ($normalized -match "^(?:[A-Za-z]:|/|\\\\)") {
        throw "TaskDefinitionFileName must be a repository-relative path under testdata/."
    }

    if (-not $normalized.StartsWith("testdata/")) {
        $normalized = "testdata/$normalized"
    }

    return $normalized
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$existingRunPids = @(Get-RunningFastmodeProcessIds -Role 'B' -RepoRoot $repoRoot -ExcludePid $PID)
if ($existingRunPids.Count -gt 0) {
    Write-Output ("[FASTMODE-B] restart_precheck existing_count={0} existing_pids={1}" -f $existingRunPids.Count, ($existingRunPids -join ','))
    $stoppedRunPids = @(Stop-RunningFastmodeProcesses -ProcessIds $existingRunPids)
    Write-Output ("[FASTMODE-B] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedRunPids.Count, ($stoppedRunPids -join ','))
}
else {
    Write-Output '[FASTMODE-B] restart_precheck existing_count=0'
}

$runMutexContext = Acquire-RunMutex -Role 'B' -RepoRoot $repoRoot
Write-Output ("[FASTMODE-B] run_mutex={0}" -f [string]$runMutexContext.Name)

$taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName $TaskDefinitionFileName
$taskDefinitionAbsolute = Join-Path $repoRoot ($taskDefinitionRelative -replace "/", [System.IO.Path]::DirectorySeparatorChar)

if (-not (Test-Path -LiteralPath $taskDefinitionAbsolute)) {
    throw "Task definition file not found: $taskDefinitionRelative"
}

if (Select-String -Path $taskDefinitionAbsolute -Pattern "TODO_" -Quiet) {
    throw "Task definition still contains TODO placeholders: $taskDefinitionRelative"
}

$remoteIp = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_IP)) { "10.0.0.199" } else { $env:AUTO_REMOTE_IP }
$remoteUser = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_USER)) { "larson" } else { $env:AUTO_REMOTE_USER }
$keyPath = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_KEYPATH)) { "/c/Users/$env:USERNAME/.ssh/id_rsa" } else { $env:AUTO_REMOTE_KEYPATH }
$queries = if ([string]::IsNullOrWhiteSpace($env:AUTO_QUERIES)) { "8.8.8.8 1.1.1.1 10.0.0.8" } else { $env:AUTO_QUERIES }
$terminalWatchdogMode = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_MODE)) { "safe" } else { $env:AUTO_TERMINAL_WATCHDOG_MODE }
$terminalWatchdogIntervalSec = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC)) { 120 } else { [int]$env:AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC }
$terminalWatchdogMinAgeSec = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC)) { 600 } else { [int]$env:AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC }

$entryScript = Join-Path $PSScriptRoot "start_dev_verify_8round_multiround.ps1"
if (-not (Test-Path -LiteralPath $entryScript)) {
    throw "Entry script not found: $entryScript"
}

Write-Output ("[FASTMODE-B] task_definition={0}" -f $taskDefinitionRelative)

$exitCode = 1
try {
    & $entryScript `
        -ResetCodeStepState `
        -CodeStepResetPolicy state-only `
        -TaskDefinitionFile $taskDefinitionRelative `
        -StartRound 1 -EndRound 8 `
        -DevVerifyStride 2 `
        -VerifyExecutionProfile d6-only `
        -EnableGuardedFastMode $true `
        -EnableGateOnlySourceDrivenSkip $true `
        -RbPreflight 1 -RbPreclassTableGuard 1 `
        -QuietTerminalOutput true `
        -TerminalWatchdogMode $terminalWatchdogMode `
        -TerminalWatchdogIntervalSec $terminalWatchdogIntervalSec `
        -TerminalWatchdogMinAgeSec $terminalWatchdogMinAgeSec `
        -QuietRemoteBuildLogs false `
        -TaskDesignQualityPolicy enforce `
        -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 `
        -DisableUnknownNoOpBudgetGate:$false `
        -KeyPath $keyPath -RemoteIp $remoteIp -User $remoteUser -Queries $queries

    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
}
finally {
    if ($null -ne $runMutexContext -and $null -ne $runMutexContext.Mutex) {
        try {
            $runMutexContext.Mutex.ReleaseMutex() | Out-Null
        }
        catch {
        }
        finally {
            $runMutexContext.Mutex.Dispose()
        }
    }
}

Write-Output ("B_EXIT={0}" -f $exitCode)
exit $exitCode
